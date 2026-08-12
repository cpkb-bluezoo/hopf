// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 control-connection protocol handler.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hopf_auth::{create_server, CredentialStore, SaslServer, SaslServerOptions, SaslServerStep};
use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, StorageError};
use hopf_mailbox::{Mailbox, MailboxFactory, MailboxStore, MessageReadCallback};
use hopf_otel::{
    ExportHandle, RequestTimer, Span, SpanKind, Trace, Pop3ServerMetrics as OtelPop3Metrics,
};
use rmimeparser::charset::base64;

use crate::server::auth::{advertised_mechanisms, apop_timestamp, capa_sasl_line, verify_apop};
use crate::server::codec::{Pop3Command, Pop3ServerLexer, MAX_COMMAND_LINE};
use crate::server::handler::{
    AuthenticateState, AuthorizationHandler, ClientConnected, ConnectedState, ListState,
    ListWriter, MailboxStatusState, MarkDeletedState, Pop3ConnectionMetadata, ResetState,
    RetrieveState, TopState, TransactionHandler, UidlState, UidlWriter, UpdateState,
};
#[cfg(test)]
use crate::server::handler::DefaultPop3HandlerFactory;
use crate::server::metrics::Pop3ServerMetrics;
use crate::server::reply;
use crate::server::service::Pop3Config;
use crate::server::session::Pop3SessionState;

/// OTel timing/span for one RETR/TOP retrieve; finished from the storage callback.
struct RetrieveTelemetry {
    timer: RequestTimer,
    span: Option<Span>,
    otel: Option<Arc<OtelPop3Metrics>>,
    kind: &'static str,
    bytes: u64,
}

impl RetrieveTelemetry {
    fn start(
        kind: &'static str,
        bytes: u64,
        otel: Option<Arc<OtelPop3Metrics>>,
        span: Option<Span>,
    ) -> Self {
        Self {
            timer: RequestTimer::start(),
            span,
            otel,
            kind,
            bytes,
        }
    }

    fn finish(self, ok: bool) {
        let outcome = if ok { "ok" } else { "fail" };
        if let Some(span) = self.span {
            span.set_attribute("pop3.retrieve.kind", self.kind);
            span.set_attribute("outcome", outcome);
            if ok {
                span.set_status_ok();
            } else {
                span.set_status_error(outcome);
            }
            span.end();
        }
        if let Some(m) = &self.otel {
            m.retrieve_completed(self.kind, outcome, self.timer.elapsed(), self.bytes);
        }
    }
}

struct MailboxBundle {
    store: Option<Box<dyn MailboxStore>>,
    mailbox: Option<Box<dyn Mailbox>>,
}

/// Per-connection POP3 protocol state machine.
pub struct Pop3ControlHandler {
    client_connected: Option<Box<dyn ClientConnected>>,
    authorization: Option<Box<dyn AuthorizationHandler>>,
    transaction: Option<Box<dyn TransactionHandler>>,
    metrics: Arc<Pop3ServerMetrics>,
    config: Pop3Config,
    runtime: Arc<Runtime>,
    lexer: Pop3ServerLexer,
    session: Pop3SessionState,
    tls: bool,
    /// SHA-256 fingerprint of the peer's mTLS client certificate, if any —
    /// fed into `SaslServerOptions.peer_certificate` for SASL EXTERNAL.
    peer_certificate: Option<String>,
    expect_implicit_tls: bool,
    greeting_sent: bool,
    stls_used: bool,
    utf8: bool,
    pending_user: Option<String>,
    apop_timestamp: String,
    sasl: Option<Box<dyn SaslServer>>,
    control_handle: Option<ConnHandle>,
    bundle: Arc<Mutex<MailboxBundle>>,
    pending_msg: u32,
    pending_top_lines: u32,
    /// Size for RETR offload scheduled after mailbox is returned to the bundle.
    pending_retr_offload: Option<u64>,
    /// Lines for TOP offload scheduled after mailbox is returned to the bundle.
    pending_top_offload: Option<u32>,
    last_auth_fail: Option<Instant>,
    last_activity: Instant,
    peer: SocketAddr,
    local: SocketAddr,
    /// Handler-visible connection metadata (includes `traceparent`).
    meta: Pop3ConnectionMetadata,
    busy: Arc<AtomicBool>,
    /// Slot for ListWriter/UidlWriter to restore the transaction handler.
    txn_slot: Arc<Mutex<Option<Box<dyn TransactionHandler>>>>,
    /// In-flight mailbox open: handler + outcome filled by the storage callback.
    pending_open: Arc<Mutex<Option<PendingOpen>>>,
    /// In-flight credential check: outcome filled by the storage callback
    /// (issue #181).
    pending_auth_check: Arc<Mutex<Option<AuthCheckOutcome>>>,
    /// Commands lexed while `busy` was set (e.g. a pipelined command right
    /// behind PASS/APOP/AUTH/RETR/TOP/QUIT), dispatched once it clears —
    /// without this, a command already parsed out of the same read as a
    /// busy-triggering one would otherwise be silently dropped rather than
    /// processed against stale state or queued correctly.
    cmd_queue: VecDeque<Pop3Command>,
    otel_metrics: Option<Arc<OtelPop3Metrics>>,
    export: Option<ExportHandle>,
    traces_enabled: bool,
    conn_trace: Option<Trace>,
}

struct PendingOpen {
    handler: Box<dyn TransactionHandler>,
    /// `None` while open is in flight; `Some(Ok(()))` / `Some(Err(()))` when done.
    outcome: Option<Result<(), ()>>,
}

/// Result of a credential check offloaded to the storage pool (issue #181)
/// — `CredentialStore::password_match`/`verify_apop`/`SaslServer::step` can
/// block for LDAP/PAM-backed stores, so all three run off the reactor
/// thread; the outcome lands here for `sync_pending_auth_check` to apply
/// once back on the reactor (the storage callback only has
/// `&mut dyn Endpoint`, never `&mut Self`).
enum AuthCheckOutcome {
    /// PASS or APOP.
    Password {
        user: String,
        result: Result<bool, String>,
    },
    /// AUTH (initial or continuation step). `first_step` marks the
    /// server-first initial call (no client data yet) — a `Complete` there
    /// means the mechanism authenticated nobody, so it's still a failure.
    Step {
        first_step: bool,
        result: Result<(Box<dyn SaslServer>, SaslServerStep), String>,
    },
}

impl Pop3ControlHandler {
    /// Create a new control handler for one accept.
    pub fn new(
        client: Box<dyn ClientConnected>,
        metrics: Arc<Pop3ServerMetrics>,
        config: Pop3Config,
        runtime: Arc<Runtime>,
    ) -> Self {
        let expect_implicit_tls = config.implicit_tls && config.tls_acceptor.is_some();
        let apop_timestamp = if config.enable_apop {
            apop_timestamp(&config.hostname)
        } else {
            String::new()
        };
        Self {
            client_connected: Some(client),
            authorization: None,
            transaction: None,
            metrics,
            config,
            runtime,
            lexer: Pop3ServerLexer::new(MAX_COMMAND_LINE),
            session: Pop3SessionState::Authorization,
            tls: false,
            peer_certificate: None,
            expect_implicit_tls,
            greeting_sent: false,
            stls_used: false,
            utf8: false,
            pending_user: None,
            apop_timestamp,
            sasl: None,
            control_handle: None,
            bundle: Arc::new(Mutex::new(MailboxBundle {
                store: None,
                mailbox: None,
            })),
            pending_msg: 0,
            pending_top_lines: 0,
            pending_retr_offload: None,
            pending_top_offload: None,
            last_auth_fail: None,
            last_activity: Instant::now(),
            peer: SocketAddr::from(([0, 0, 0, 0], 0)),
            local: SocketAddr::from(([0, 0, 0, 0], 0)),
            meta: Pop3ConnectionMetadata {
                peer: SocketAddr::from(([0, 0, 0, 0], 0)),
                local: SocketAddr::from(([0, 0, 0, 0], 0)),
                tls: false,
                traceparent: None,
            },
            busy: Arc::new(AtomicBool::new(false)),
            txn_slot: Arc::new(Mutex::new(None)),
            pending_open: Arc::new(Mutex::new(None)),
            pending_auth_check: Arc::new(Mutex::new(None)),
            cmd_queue: VecDeque::new(),
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            conn_trace: None,
        }
    }

    /// Attach OTel metrics / traces from a telemetry pipeline.
    pub fn with_telemetry(
        mut self,
        otel_metrics: Option<Arc<OtelPop3Metrics>>,
        export: Option<ExportHandle>,
        traces_enabled: bool,
    ) -> Self {
        self.otel_metrics = otel_metrics;
        self.export = export;
        self.traces_enabled = traces_enabled;
        self
    }

    fn sync_meta_addrs(&mut self) {
        self.meta.peer = self.peer;
        self.meta.local = self.local;
        self.meta.tls = self.tls;
    }

    fn begin_connection_telemetry(&mut self) {
        if let Some(m) = &self.otel_metrics {
            m.connection_opened();
        }
        if self.traces_enabled {
            if let Some(export) = self.export.clone() {
                let t = Trace::new("POP3 connection", SpanKind::Server);
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
            m.connection_closed();
        }
    }

    fn begin_retrieve_telemetry(
        &mut self,
        kind: &'static str,
        bytes: u64,
    ) -> Option<RetrieveTelemetry> {
        if self.otel_metrics.is_none() && self.conn_trace.is_none() {
            return None;
        }
        let span = if let Some(trace) = &self.conn_trace {
            let s = trace.start_span("POP3 retrieve", SpanKind::Server);
            self.meta.traceparent = Some(trace.traceparent());
            Some(s)
        } else {
            None
        };
        Some(RetrieveTelemetry::start(
            kind,
            bytes,
            self.otel_metrics.clone(),
            span,
        ))
    }

    fn record_auth(&self, ok: bool) {
        if ok {
            Pop3ServerMetrics::add(&self.metrics.auth_ok, 1);
        } else {
            Pop3ServerMetrics::add(&self.metrics.auth_fail, 1);
        }
        if let Some(m) = &self.otel_metrics {
            m.auth(ok);
        }
    }

    fn record_stls(&self) {
        Pop3ServerMetrics::add(&self.metrics.stls, 1);
        if let Some(m) = &self.otel_metrics {
            m.stls();
        }
    }

    /// Apply mailbox-open result after the storage callback (reactor turn).
    fn sync_pending_open(&mut self) {
        let mut slot = self.pending_open.lock().unwrap();
        let Some(pending) = slot.as_mut() else {
            return;
        };
        let Some(outcome) = pending.outcome.take() else {
            return;
        };
        let PendingOpen { handler, .. } = slot.take().unwrap();
        match outcome {
            Ok(()) => {
                self.transaction = Some(handler);
                self.session = Pop3SessionState::Transaction;
                self.authorization = None;
            }
            Err(()) => {
                // Stay in AUTHORIZATION; keep authorization handler for retry.
                let _ = handler;
            }
        }
    }

    fn send(&mut self, endpoint: &mut dyn Endpoint, bytes: Vec<u8>) {
        endpoint.send(&bytes);
    }

    fn greet(&mut self, endpoint: &mut dyn Endpoint) {
        if self.greeting_sent {
            return;
        }
        self.greeting_sent = true;
        Pop3ServerMetrics::add(&self.metrics.connections, 1);
        self.sync_meta_addrs();
        let mut view = ConnectedView {
            endpoint,
            authorization: &mut self.authorization,
            apop_timestamp: &self.apop_timestamp,
            enable_apop: self.config.enable_apop,
        };
        if let Some(mut c) = self.client_connected.take() {
            c.connected(&mut view, &self.meta);
            self.client_connected = Some(c);
        }
    }

    fn dispatch(&mut self, endpoint: &mut dyn Endpoint, cmd: Pop3Command) {
        // SASL continuation lines bypass every other check (busy / UPDATE
        // state / session dispatch) exactly as a raw "+"-prompted line
        // always did — they aren't really commands.
        if matches!(
            cmd,
            Pop3Command::SaslResponse(_)
                | Pop3Command::SaslAbort
                | Pop3Command::SaslResponseInvalid
        ) {
            match cmd {
                Pop3Command::SaslResponse(data) => self.handle_sasl_response(endpoint, data),
                Pop3Command::SaslAbort => {
                    self.sasl = None;
                    self.send(endpoint, reply::err("[AUTH] Authentication cancelled"));
                }
                Pop3Command::SaslResponseInvalid => {
                    self.sasl = None;
                    self.auth_failed(endpoint, "[AUTH] Invalid base64");
                }
                _ => unreachable!(),
            }
            return;
        }

        self.last_activity = Instant::now();
        self.take_txn_slot();
        if self.busy.load(Ordering::Relaxed) {
            self.send(
                endpoint,
                reply::err("[SYS/TEMP] Server busy, try again later"),
            );
            return;
        }
        if self.session == Pop3SessionState::Update {
            self.send(endpoint, reply::err("Command not valid in UPDATE state"));
            return;
        }

        match cmd {
            Pop3Command::Capa => self.cmd_capa(endpoint),
            Pop3Command::Noop => self.send(endpoint, reply::ok_bare()),
            Pop3Command::Quit => self.cmd_quit(endpoint),
            Pop3Command::Stls => self.cmd_stls(endpoint),
            Pop3Command::Utf8 => self.cmd_utf8(endpoint),
            _ if self.session == Pop3SessionState::Authorization => {
                self.dispatch_auth(endpoint, cmd);
            }
            _ if self.session == Pop3SessionState::Transaction => {
                self.dispatch_txn(endpoint, cmd);
            }
            _ => self.send(endpoint, reply::err("Unknown command")),
        }
    }

    fn dispatch_auth(&mut self, endpoint: &mut dyn Endpoint, cmd: Pop3Command) {
        match cmd {
            Pop3Command::User(name) => {
                if name.is_empty() {
                    self.send(endpoint, reply::err("Missing username"));
                    return;
                }
                self.pending_user = Some(name);
                self.send(endpoint, reply::ok("User accepted"));
            }
            Pop3Command::Pass(password) => self.cmd_pass(endpoint, &password),
            Pop3Command::Apop { name, digest } => self.cmd_apop(endpoint, &name, &digest),
            Pop3Command::AuthList => self.cmd_auth_list(endpoint),
            Pop3Command::Auth {
                mechanism,
                initial_response,
            } => self.cmd_auth(endpoint, &mechanism, initial_response),
            Pop3Command::Malformed { verb } => {
                self.send(endpoint, reply::err(&format!("Syntax error in {verb}")));
            }
            _ => self.send(
                endpoint,
                reply::err("Command not valid in AUTHORIZATION state"),
            ),
        }
    }

    fn dispatch_txn(&mut self, endpoint: &mut dyn Endpoint, cmd: Pop3Command) {
        if self.last_activity.elapsed() > self.config.transaction_timeout {
            self.send(endpoint, reply::err("[SYS/TEMP] Transaction timeout"));
            endpoint.close();
            return;
        }
        match cmd {
            Pop3Command::Stat => self.cmd_stat(endpoint),
            Pop3Command::List(n) => self.cmd_list(endpoint, n),
            Pop3Command::Retr(n) => self.cmd_retr(endpoint, n),
            Pop3Command::Dele(n) => self.cmd_dele(endpoint, n),
            Pop3Command::Rset => self.cmd_rset(endpoint),
            Pop3Command::Top(n, lines) => self.cmd_top(endpoint, n, lines),
            Pop3Command::Uidl(n) => self.cmd_uidl(endpoint, n),
            Pop3Command::User(_)
            | Pop3Command::Pass(_)
            | Pop3Command::Apop { .. }
            | Pop3Command::AuthList
            | Pop3Command::Auth { .. } => self.send(endpoint, reply::err("Already authenticated")),
            Pop3Command::Malformed { verb } => {
                self.send(endpoint, reply::err(&format!("Syntax error in {verb}")));
            }
            _ => self.send(endpoint, reply::err("Unknown command")),
        }
    }

    fn cmd_capa(&mut self, endpoint: &mut dyn Endpoint) {
        self.send(endpoint, reply::ok("Capability list follows"));
        let mut lines = vec![
            "USER".to_string(),
            "UIDL".to_string(),
            "TOP".to_string(),
            "RESP-CODES".to_string(),
            "AUTH-RESP-CODE".to_string(),
            "IMPLEMENTATION hopf".to_string(),
        ];
        if self.config.enable_utf8 {
            // RFC 6856 §2.2: USER argument means UTF-8 usernames/passwords
            // are accepted (including before the UTF8 command).
            lines.push("UTF8 USER".to_string());
        }
        if self.config.enable_pipelining {
            lines.push("PIPELINING".to_string());
        }
        if self.config.enable_apop {
            lines.push("APOP".to_string());
        }
        if !self.tls && self.config.tls_acceptor.is_some() && !self.config.implicit_tls {
            lines.push("STLS".to_string());
        }
        if let Some(d) = self.config.expire_days {
            lines.push(format!("EXPIRE {d}"));
        }
        if !self.config.login_delay.is_zero() {
            lines.push(format!(
                "LOGIN-DELAY {}",
                self.config.login_delay.as_secs().max(1)
            ));
        }
        let mechs = advertised_mechanisms(&self.config.store, self.tls);
        if let Some(s) = capa_sasl_line(&mechs) {
            lines.push(s);
        }
        for l in lines {
            self.send(endpoint, reply::line(&l));
        }
        self.send(endpoint, reply::multiline_end());
    }

    fn cmd_stls(&mut self, endpoint: &mut dyn Endpoint) {
        if self.session != Pop3SessionState::Authorization {
            self.send(
                endpoint,
                reply::err("STLS only valid in AUTHORIZATION state"),
            );
            return;
        }
        // RFC 6856 §2.1: clients MUST NOT issue STLS after UTF8; servers MAY reject.
        if self.utf8 {
            self.send(endpoint, reply::err("STLS not allowed after UTF8"));
            return;
        }
        if self.tls {
            self.send(endpoint, reply::err("TLS already active"));
            return;
        }
        if self.config.tls_acceptor.is_none() || self.config.implicit_tls {
            self.send(endpoint, reply::err("TLS not available"));
            return;
        }
        self.send(endpoint, reply::ok("Begin TLS negotiation"));
        self.stls_used = true;
        let _ = endpoint.start_tls();
    }

    fn cmd_utf8(&mut self, endpoint: &mut dyn Endpoint) {
        if self.session != Pop3SessionState::Authorization {
            self.send(
                endpoint,
                reply::err("UTF8 only valid in AUTHORIZATION state"),
            );
            return;
        }
        if !self.config.enable_utf8 {
            self.send(endpoint, reply::err("UTF8 not available"));
            return;
        }
        self.utf8 = true;
        self.send(endpoint, reply::ok("UTF8 mode enabled"));
    }

    fn login_delay_active(&self) -> bool {
        if self.config.login_delay.is_zero() {
            return false;
        }
        self.last_auth_fail
            .map(|t| t.elapsed() < self.config.login_delay)
            .unwrap_or(false)
    }

    fn auth_failed(&mut self, endpoint: &mut dyn Endpoint, msg: &str) {
        self.record_auth(false);
        self.last_auth_fail = Some(Instant::now());
        self.pending_user = None;
        self.send(endpoint, reply::err(msg));
    }

    fn cmd_pass(&mut self, endpoint: &mut dyn Endpoint, password: &str) {
        if self.login_delay_active() {
            self.send(endpoint, reply::err("[AUTH] Login delay active"));
            return;
        }
        let Some(user) = self.pending_user.clone() else {
            self.send(endpoint, reply::err("USER required first"));
            return;
        };
        let Some(handle) = self.control_handle.clone() else {
            self.send(endpoint, reply::err("[SYS/TEMP] No connection handle"));
            return;
        };
        let store = Arc::clone(&self.config.store);
        let password = password.to_owned();
        let user_for_check = user.clone();
        let pending = Arc::clone(&self.pending_auth_check);
        let busy = Arc::clone(&self.busy);
        self.set_busy(true);
        endpoint.pause_read();
        self.runtime.storage().submit_on(
            handle.clone(),
            move || Ok(store.password_match(&user_for_check, &password)),
            move |result: Result<bool, StorageError>| {
                let result = result.map_err(|e| e.to_string());
                *pending.lock().unwrap() = Some(AuthCheckOutcome::Password { user, result });
                handle.with_endpoint(move |ep| {
                    busy.store(false, Ordering::Relaxed);
                    ep.resume_read();
                    // Unlike RETR/TOP/mailbox-open, nothing has been sent to
                    // the client yet at this point — the reply depends
                    // entirely on `sync_pending_auth_check`, which needs
                    // `&mut Self` and so can't run from here. The client is
                    // waiting on us, not about to send more input, so
                    // `resume_read` alone would never trigger another
                    // `receive()` call; `poke_handler` forces one.
                    ep.poke_handler();
                });
            },
        );
    }

    fn cmd_apop(&mut self, endpoint: &mut dyn Endpoint, user: &str, digest: &str) {
        if !self.config.enable_apop {
            self.send(endpoint, reply::err("APOP not available"));
            return;
        }
        if self.login_delay_active() {
            self.send(endpoint, reply::err("[AUTH] Login delay active"));
            return;
        }
        let Some(handle) = self.control_handle.clone() else {
            self.send(endpoint, reply::err("[SYS/TEMP] No connection handle"));
            return;
        };
        let store = Arc::clone(&self.config.store);
        let user = user.to_owned();
        let user_for_check = user.clone();
        let timestamp = self.apop_timestamp.clone();
        let digest = digest.to_owned();
        let pending = Arc::clone(&self.pending_auth_check);
        let busy = Arc::clone(&self.busy);
        self.set_busy(true);
        endpoint.pause_read();
        self.runtime.storage().submit_on(
            handle.clone(),
            move || Ok(verify_apop(store.as_ref(), &user_for_check, &timestamp, &digest)),
            move |result: Result<bool, StorageError>| {
                let result = result.map_err(|e| e.to_string());
                *pending.lock().unwrap() = Some(AuthCheckOutcome::Password { user, result });
                handle.with_endpoint(move |ep| {
                    busy.store(false, Ordering::Relaxed);
                    ep.resume_read();
                    ep.poke_handler();
                });
            },
        );
    }

    fn cmd_auth_list(&mut self, endpoint: &mut dyn Endpoint) {
        if self.login_delay_active() {
            self.send(endpoint, reply::err("[AUTH] Login delay active"));
            return;
        }
        // RFC 1734-style listing
        self.send(endpoint, reply::ok("Supported authentication mechanisms:"));
        for m in advertised_mechanisms(&self.config.store, self.tls) {
            self.send(endpoint, reply::line(m.name()));
        }
        self.send(endpoint, reply::multiline_end());
    }

    fn cmd_auth(
        &mut self,
        endpoint: &mut dyn Endpoint,
        mechanism: &str,
        initial_response: Option<Vec<u8>>,
    ) {
        if self.login_delay_active() {
            self.send(endpoint, reply::err("[AUTH] Login delay active"));
            return;
        }
        let Some(mech) = hopf_auth::SaslMechanism::from_name(mechanism) else {
            self.send(endpoint, reply::err("[AUTH] Unsupported mechanism"));
            return;
        };
        if mech.requires_tls() && !self.tls {
            self.send(
                endpoint,
                reply::err("[AUTH] Encryption required for requested authentication mechanism"),
            );
            return;
        }
        let opts = SaslServerOptions {
            hostname: self.config.hostname.clone(),
            realm: self.config.hostname.clone(),
            peer_certificate: self.peer_certificate.clone(),
            channel_binding: None,
        };
        let server = create_server(mech, Arc::clone(&self.config.store), opts);

        if server.server_first() && initial_response.is_none() {
            // A server-first mechanism must send its challenge before any
            // client response exists to step on — "complete" here would
            // mean the mechanism authenticated nobody, so it's still a
            // failure (see `AuthCheckOutcome::Step::first_step`).
            self.sasl_step(endpoint, server, None, true);
            return;
        }

        self.sasl_step(endpoint, server, initial_response.as_deref(), false);
    }

    /// Run one SASL step off the reactor thread (issue #181 —
    /// `SaslServer::step` can block for LDAP/PAM-backed stores). The result
    /// is applied later by `sync_pending_auth_check`, once back on the
    /// reactor; `busy` gates pipelined commands until then.
    fn sasl_step(
        &mut self,
        endpoint: &mut dyn Endpoint,
        mut server: Box<dyn SaslServer>,
        response: Option<&[u8]>,
        first_step: bool,
    ) {
        let Some(handle) = self.control_handle.clone() else {
            self.send(endpoint, reply::err("[SYS/TEMP] No connection handle"));
            return;
        };
        let response = response.map(<[u8]>::to_vec);
        let pending = Arc::clone(&self.pending_auth_check);
        let busy = Arc::clone(&self.busy);
        self.set_busy(true);
        endpoint.pause_read();
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                // `step()` is callback-based (may complete inline, or hand
                // off to e.g. an OAUTHBEARER introspection transport);
                // bridge back to `submit_on`'s synchronous-`op` contract.
                // This closure already runs on a storage-pool thread, never
                // the reactor, so blocking here is exactly what
                // `StorageExecutor` is for (issue #182).
                let (tx, rx) = std::sync::mpsc::channel();
                server.step(response.as_deref(), Box::new(move |step| {
                    let _ = tx.send(step);
                }));
                let step = rx.recv().map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                    "SaslServer::step callback dropped without completing".into()
                })?;
                Ok((server, step))
            },
            move |result: Result<(Box<dyn SaslServer>, SaslServerStep), StorageError>| {
                let result = result.map_err(|e| e.to_string());
                *pending.lock().unwrap() = Some(AuthCheckOutcome::Step { first_step, result });
                handle.with_endpoint(move |ep| {
                    busy.store(false, Ordering::Relaxed);
                    ep.resume_read();
                    ep.poke_handler();
                });
            },
        );
    }

    fn handle_sasl_response(&mut self, endpoint: &mut dyn Endpoint, response: Vec<u8>) {
        let Some(server) = self.sasl.take() else {
            return;
        };
        self.sasl_step(endpoint, server, Some(&response), false);
    }

    /// Apply the outcome of an offloaded credential check (PASS/APOP or a
    /// SASL step), once `submit_on`'s callback has stashed one — see
    /// `AuthCheckOutcome`.
    fn sync_pending_auth_check(&mut self, endpoint: &mut dyn Endpoint) {
        let Some(outcome) = self.pending_auth_check.lock().unwrap().take() else {
            return;
        };
        match outcome {
            AuthCheckOutcome::Password { user, result } => match result {
                Ok(true) => self.finish_auth(endpoint, &user),
                Ok(false) => self.auth_failed(endpoint, "[AUTH] Authentication failed"),
                Err(e) => self.send(
                    endpoint,
                    reply::err(&format!("[SYS/TEMP] Authentication temporarily unavailable: {e}")),
                ),
            },
            AuthCheckOutcome::Step { first_step, result } => match result {
                Ok((server, step)) => match step {
                    SaslServerStep::Challenge(c) => {
                        self.send(endpoint, reply::continuation(&base64::encode(&c)));
                        self.sasl = Some(server);
                        self.lexer.expect_sasl_response();
                    }
                    SaslServerStep::Complete {
                        username,
                        final_message,
                    } if !first_step => {
                        if let Some(fm) = final_message {
                            if !fm.is_empty() {
                                self.send(endpoint, reply::continuation(&base64::encode(&fm)));
                            }
                        }
                        self.finish_auth(endpoint, &username);
                    }
                    SaslServerStep::Complete { .. } | SaslServerStep::Failure => {
                        self.auth_failed(endpoint, "[AUTH] Authentication failed");
                    }
                },
                Err(e) => self.send(
                    endpoint,
                    reply::err(&format!("[SYS/TEMP] Authentication temporarily unavailable: {e}")),
                ),
            },
        }
    }

    fn finish_auth(&mut self, endpoint: &mut dyn Endpoint, username: &str) {
        self.record_auth(true);
        self.pending_user = None;
        let factory = Arc::clone(&self.config.mailbox_factory);
        let Some(mut h) = self.authorization.take() else {
            self.send(endpoint, reply::err("[SYS/PERM] No authorization handler"));
            return;
        };
        let mut view = AuthView {
            endpoint,
            authorization: &mut self.authorization,
            bundle: &self.bundle,
            runtime: &self.runtime,
            control_handle: &self.control_handle,
            busy: &self.busy,
            pending_open: &self.pending_open,
            username: username.to_string(),
            factory: Arc::clone(&factory),
        };
        h.authenticate(&mut view, username, factory.as_ref());
        // Keep authorization until mailbox open succeeds (`sync_pending_open`).
        if self.authorization.is_none() && self.session == Pop3SessionState::Authorization {
            self.authorization = Some(h);
        }
        self.sync_pending_open();
    }

    fn take_txn_slot(&mut self) {
        if let Some(h) = self.txn_slot.lock().unwrap().take() {
            self.transaction = Some(h);
        }
    }

    fn set_busy(&self, v: bool) {
        self.busy.store(v, Ordering::Relaxed);
    }

    /// Dispatch a queued command once `busy` clears — mirrors `hopf-imap`'s
    /// identically-named helper.
    fn drain_queue(&mut self, endpoint: &mut dyn Endpoint) {
        while !self.busy.load(Ordering::Relaxed) {
            let Some(cmd) = self.cmd_queue.pop_front() else {
                break;
            };
            self.dispatch(endpoint, cmd);
        }
    }

    fn enqueue_or_dispatch(&mut self, endpoint: &mut dyn Endpoint, cmd: Pop3Command) {
        if self.busy.load(Ordering::Relaxed) {
            self.cmd_queue.push_back(cmd);
        } else {
            self.dispatch(endpoint, cmd);
        }
    }

    fn with_mailbox_mut<R>(
        &mut self,
        f: impl FnOnce(&mut dyn Mailbox, &mut Self) -> R,
    ) -> Option<R> {
        let mut mb = {
            let mut g = self.bundle.lock().unwrap();
            g.mailbox.take()
        }?;
        let r = f(mb.as_mut(), self);
        self.bundle.lock().unwrap().mailbox = Some(mb);
        Some(r)
    }

    fn with_mailbox_ref<R>(&mut self, f: impl FnOnce(&dyn Mailbox, &mut Self) -> R) -> Option<R> {
        let mb = {
            let mut g = self.bundle.lock().unwrap();
            g.mailbox.take()
        }?;
        let r = f(mb.as_ref(), self);
        self.bundle.lock().unwrap().mailbox = Some(mb);
        Some(r)
    }

    /// RFC 6856 §2.1 / §5: without UTF8 mode, refuse messages that contain
    /// octets outside the ASCII repertoire (rather than inventing a surrogate).
    fn message_requires_utf8(&mut self, message_number: u32) -> bool {
        self.with_mailbox_mut(|mb, _| message_has_non_ascii(mb, message_number))
            .unwrap_or(false)
    }

    fn cmd_stat(&mut self, endpoint: &mut dyn Endpoint) {
        let Some(mut handler) = self.transaction.take() else {
            self.send(endpoint, reply::err("[SYS/PERM] No handler"));
            return;
        };
        let mut done = false;
        self.with_mailbox_ref(|mb, this| {
            let mut view = StatusView {
                endpoint,
                transaction: &mut this.transaction,
            };
            handler.mailbox_status(&mut view, mb);
            done = true;
        });
        if !done {
            self.transaction = Some(handler);
            self.send(endpoint, reply::err("[SYS/TEMP] Mailbox not open"));
        } else if self.transaction.is_none() {
            self.transaction = Some(handler);
        }
    }

    fn cmd_list(&mut self, endpoint: &mut dyn Endpoint, n: Option<u32>) {
        if let Some(msg) = n {
            if !self.utf8 && self.message_requires_utf8(msg) {
                self.send(
                    endpoint,
                    reply::err("[UTF8] UTF8 mode required to access this message"),
                );
                return;
            }
        }
        let Some(mut handler) = self.transaction.take() else {
            self.send(endpoint, reply::err("[SYS/PERM] No handler"));
            return;
        };
        let handle = endpoint.handle();
        let txn_slot = Arc::clone(&self.txn_slot);
        let mut done = false;
        self.with_mailbox_ref(|mb, this| {
            let mut view = ListView {
                endpoint,
                transaction: &mut this.transaction,
                handle: handle.clone(),
                txn_slot: Arc::clone(&txn_slot),
            };
            handler.list(&mut view, mb, n.unwrap_or(0));
            done = true;
        });
        self.take_txn_slot();
        if !done {
            self.transaction = Some(handler);
            self.send(endpoint, reply::err("[SYS/TEMP] Mailbox not open"));
        } else if self.transaction.is_none() {
            self.transaction = Some(handler);
        }
    }

    fn cmd_retr(&mut self, endpoint: &mut dyn Endpoint, n: u32) {
        self.pending_msg = n;
        let Some(mut handler) = self.transaction.take() else {
            self.send(endpoint, reply::err("[SYS/PERM] No handler"));
            return;
        };
        let mut done = false;
        self.with_mailbox_ref(|mb, this| {
            let mut view = RetrView {
                endpoint,
                control: this,
            };
            handler.retrieve_message(&mut view, mb, n);
            done = true;
        });
        if !done {
            self.transaction = Some(handler);
            self.pending_retr_offload = None;
            self.send(endpoint, reply::err("[SYS/TEMP] Mailbox not open"));
        } else if self.transaction.is_none() {
            self.transaction = Some(handler);
        }
        if let Some(size) = self.pending_retr_offload.take() {
            if !self.utf8 && self.message_requires_utf8(self.pending_msg) {
                self.send(
                    endpoint,
                    reply::err("[UTF8] UTF8 mode required to retrieve this message"),
                );
                return;
            }
            self.start_retr_offload(endpoint, size);
        }
    }

    fn cmd_dele(&mut self, endpoint: &mut dyn Endpoint, n: u32) {
        let Some(mut handler) = self.transaction.take() else {
            self.send(endpoint, reply::err("[SYS/PERM] No handler"));
            return;
        };
        let mut done = false;
        self.with_mailbox_mut(|mb, this| {
            let mut view = DeleView {
                endpoint,
                transaction: &mut this.transaction,
                metrics: &this.metrics,
                otel: &this.otel_metrics,
            };
            handler.mark_deleted(&mut view, mb, n);
            done = true;
        });
        if !done {
            self.transaction = Some(handler);
            self.send(endpoint, reply::err("[SYS/TEMP] Mailbox not open"));
        } else if self.transaction.is_none() {
            self.transaction = Some(handler);
        }
    }

    fn cmd_rset(&mut self, endpoint: &mut dyn Endpoint) {
        let Some(mut handler) = self.transaction.take() else {
            self.send(endpoint, reply::err("[SYS/PERM] No handler"));
            return;
        };
        let mut done = false;
        self.with_mailbox_mut(|mb, this| {
            let mut view = RsetView {
                endpoint,
                transaction: &mut this.transaction,
            };
            handler.reset(&mut view, mb);
            done = true;
        });
        if !done {
            self.transaction = Some(handler);
            self.send(endpoint, reply::err("[SYS/TEMP] Mailbox not open"));
        } else if self.transaction.is_none() {
            self.transaction = Some(handler);
        }
    }

    fn cmd_top(&mut self, endpoint: &mut dyn Endpoint, n: u32, lines: u32) {
        self.pending_msg = n;
        self.pending_top_lines = lines;
        let Some(mut handler) = self.transaction.take() else {
            self.send(endpoint, reply::err("[SYS/PERM] No handler"));
            return;
        };
        let mut done = false;
        self.with_mailbox_ref(|mb, this| {
            let mut view = TopView {
                endpoint,
                control: this,
            };
            handler.top(&mut view, mb, n, lines);
            done = true;
        });
        if !done {
            self.transaction = Some(handler);
            self.pending_top_offload = None;
            self.send(endpoint, reply::err("[SYS/TEMP] Mailbox not open"));
        } else if self.transaction.is_none() {
            self.transaction = Some(handler);
        }
        if let Some(lines) = self.pending_top_offload.take() {
            if !self.utf8 && self.message_requires_utf8(self.pending_msg) {
                self.send(
                    endpoint,
                    reply::err("[UTF8] UTF8 mode required to retrieve this message"),
                );
                return;
            }
            self.start_top_offload(endpoint, lines);
        }
    }

    fn cmd_uidl(&mut self, endpoint: &mut dyn Endpoint, n: Option<u32>) {
        let Some(mut handler) = self.transaction.take() else {
            self.send(endpoint, reply::err("[SYS/PERM] No handler"));
            return;
        };
        let handle = endpoint.handle();
        let txn_slot = Arc::clone(&self.txn_slot);
        let mut done = false;
        self.with_mailbox_ref(|mb, this| {
            let mut view = UidlView {
                endpoint,
                transaction: &mut this.transaction,
                handle: handle.clone(),
                txn_slot: Arc::clone(&txn_slot),
            };
            handler.uidl(&mut view, mb, n.unwrap_or(0));
            done = true;
        });
        self.take_txn_slot();
        if !done {
            self.transaction = Some(handler);
            self.send(endpoint, reply::err("[SYS/TEMP] Mailbox not open"));
        } else if self.transaction.is_none() {
            self.transaction = Some(handler);
        }
    }

    fn cmd_quit(&mut self, endpoint: &mut dyn Endpoint) {
        match self.session {
            Pop3SessionState::Authorization => {
                self.send(endpoint, reply::ok("Goodbye"));
                endpoint.close();
            }
            Pop3SessionState::Transaction => {
                self.session = Pop3SessionState::Update;
                let Some(mut handler) = self.transaction.take() else {
                    self.send(endpoint, reply::ok("Goodbye"));
                    endpoint.close();
                    return;
                };
                let mut done = false;
                self.with_mailbox_ref(|mb, this| {
                    let mut view = QuitView {
                        endpoint,
                        control: this,
                    };
                    handler.quit(&mut view, mb);
                    done = true;
                });
                if !done {
                    self.send(endpoint, reply::ok("Goodbye"));
                    endpoint.close();
                }
            }
            Pop3SessionState::Update => {
                self.send(endpoint, reply::err("Command not valid in UPDATE state"));
            }
        }
    }

    fn start_retr_offload(&mut self, endpoint: &mut dyn Endpoint, size: u64) {
        let msg = self.pending_msg;
        let bundle = Arc::clone(&self.bundle);
        let handle = endpoint.handle();
        let metrics = Arc::clone(&self.metrics);
        let busy = Arc::clone(&self.busy);
        let telemetry = self.begin_retrieve_telemetry("retr", size);
        self.set_busy(true);
        endpoint.pause_read();
        // The status line is sent up front — `size` is already known from
        // mailbox metadata, so this doesn't need the storage round trip.
        // Only a rare mid-stream I/O error (mailbox closed concurrently, a
        // disk fault) can still happen after this; that closes the
        // connection instead of trying to report an error mid-response,
        // which POP3's framing has no way to do gracefully once `+OK` has
        // already gone out — see `Pop3DotStuffer`.
        self.send(endpoint, reply::ok(&format!("{size} octets")));
        Pop3ServerMetrics::add(&metrics.retr, 1);
        self.runtime.storage().submit_streamed(
            handle.clone(),
            move |push| {
                let mut g = bundle.lock().unwrap();
                let mb = g
                    .mailbox
                    .as_mut()
                    .ok_or_else(|| "mailbox closed".to_string())?;
                let conn = push.clone();
                let mut cb = PushDotStuffer::new(move |bytes: &[u8]| conn.send(bytes.to_vec()));
                let result = mb.read_message(msg, &mut cb).map_err(|e| e.to_string());
                cb.finish();
                result?;
                Ok(())
            },
            move |result: Result<(), StorageError>| {
                let ok = result.is_ok();
                if let Err(e) = result {
                    // The status line already went out; nothing left to do
                    // but log and let the client observe a truncated
                    // download / closed connection.
                    eprintln!("hopf-pop3: RETR failed mid-stream: {e}");
                }
                if let Some(tel) = telemetry {
                    tel.finish(ok);
                }
                handle.with_endpoint(move |ep| {
                    busy.store(false, Ordering::Relaxed);
                    ep.resume_read();
                    // See the identical comment in `AuthView::proceed_open`
                    // — a command pipelined right behind RETR can be
                    // sitting in `cmd_queue` at this point (issue #181).
                    ep.poke_handler();
                });
            },
        );
    }

    fn start_top_offload(&mut self, endpoint: &mut dyn Endpoint, lines: u32) {
        let msg = self.pending_msg;
        let bundle = Arc::clone(&self.bundle);
        let handle = endpoint.handle();
        let busy = Arc::clone(&self.busy);
        let telemetry = self.begin_retrieve_telemetry("top", 0);
        self.set_busy(true);
        endpoint.pause_read();
        self.send(endpoint, reply::ok("Top of message follows"));
        self.runtime.storage().submit_streamed(
            handle.clone(),
            move |push| {
                let mut g = bundle.lock().unwrap();
                let mb = g
                    .mailbox
                    .as_mut()
                    .ok_or_else(|| "mailbox closed".to_string())?;
                let conn = push.clone();
                let mut cb = TopPushCallback::new(move |bytes: &[u8]| conn.send(bytes.to_vec()), lines);
                let result = mb.read_message(msg, &mut cb).map_err(|e| e.to_string());
                cb.finish();
                result?;
                Ok(())
            },
            move |result: Result<(), StorageError>| {
                let ok = result.is_ok();
                if let Err(e) = result {
                    eprintln!("hopf-pop3: TOP failed mid-stream: {e}");
                }
                if let Some(tel) = telemetry {
                    tel.finish(ok);
                }
                handle.with_endpoint(move |ep| {
                    busy.store(false, Ordering::Relaxed);
                    ep.resume_read();
                    // See the identical comment in `AuthView::proceed_open`
                    // — a command pipelined right behind TOP can be
                    // sitting in `cmd_queue` at this point (issue #181).
                    ep.poke_handler();
                });
            },
        );
    }

    fn start_quit_offload(&mut self, endpoint: &mut dyn Endpoint) {
        let bundle = Arc::clone(&self.bundle);
        let handle = endpoint.handle();
        let busy = Arc::clone(&self.busy);
        self.set_busy(true);
        endpoint.pause_read();
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut g = bundle.lock().unwrap();
                if let Some(mut mb) = g.mailbox.take() {
                    mb.close(true).map_err(|e| e.to_string())?;
                }
                if let Some(mut st) = g.store.take() {
                    st.close().map_err(|e| e.to_string())?;
                }
                Ok(())
            },
            move |result: Result<(), StorageError>| {
                handle.with_endpoint(move |ep| {
                    match result {
                        Ok(()) => ep.send(&reply::ok("Goodbye, messages deleted")),
                        Err(e) => ep.send(&reply::err(&format!(
                            "[SYS/TEMP] Some deleted messages may not be removed: {e}"
                        ))),
                    }
                    busy.store(false, Ordering::Relaxed);
                    ep.close();
                });
            },
        );
    }

    fn offload_close_no_expunge(&self) {
        let bundle = Arc::clone(&self.bundle);
        let Some(handle) = self.control_handle.clone() else {
            return;
        };
        self.runtime.storage().submit_on(
            handle,
            move || {
                let mut g = bundle.lock().unwrap();
                if let Some(mut mb) = g.mailbox.take() {
                    let _ = mb.close(false);
                }
                if let Some(mut st) = g.store.take() {
                    let _ = st.close();
                }
                Ok(())
            },
            move |_r: Result<(), StorageError>| {},
        );
    }
}

impl ProtocolHandler for Pop3ControlHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Ok(peer) = endpoint.remote_addr() {
            self.peer = peer;
        }
        if let Ok(local) = endpoint.local_addr() {
            self.local = local;
        }
        if endpoint.is_secure() {
            self.tls = true;
        }
        self.sync_meta_addrs();
        self.begin_connection_telemetry();
        self.control_handle = Some(endpoint.handle());
        if !self.expect_implicit_tls || self.tls {
            self.greet(endpoint);
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.sync_pending_open();
        self.sync_pending_auth_check(endpoint);
        self.take_txn_slot();
        self.drain_queue(endpoint);

        if self.busy.load(Ordering::Relaxed) {
            // Reads are paused during storage offloads; drop any residual.
            *data = &[];
            return;
        }

        let cmds = self.lexer.feed(data);
        if self.lexer.took_line_too_long() {
            self.send(endpoint, reply::err("Line too long"));
        }
        for cmd in cmds {
            // While busy, queue instead of dropping — a command already
            // lexed out of this same buffer (e.g. pipelined right behind
            // PASS/APOP/AUTH) must not be lost just because a prior command
            // in this same batch started a storage offload.
            self.enqueue_or_dispatch(endpoint, cmd);
        }
        self.sync_pending_open();
        self.sync_pending_auth_check(endpoint);
        self.drain_queue(endpoint);
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if let Some(mut c) = self.client_connected.take() {
            c.disconnected();
        }
        if self.session != Pop3SessionState::Update {
            self.offload_close_no_expunge();
        }
        self.end_connection_telemetry();
    }

    fn security_established(
        &mut self,
        endpoint: &mut dyn Endpoint,
        info: &hopf_core::SecurityInfo,
    ) {
        let first = !self.tls;
        self.tls = true;
        self.meta.tls = true;
        self.peer_certificate = info.peer_certificate_fingerprint().map(str::to_string);
        if self.expect_implicit_tls && !self.greeting_sent {
            self.greet(endpoint);
            return;
        }
        if self.stls_used {
            self.record_stls();
            self.stls_used = false;
            return;
        }
        let _ = first;
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &std::io::Error) {
        endpoint.close();
    }
}

// ----- state views -----

struct ConnectedView<'a> {
    endpoint: &'a mut dyn Endpoint,
    authorization: &'a mut Option<Box<dyn AuthorizationHandler>>,
    apop_timestamp: &'a str,
    enable_apop: bool,
}

impl ConnectedState for ConnectedView<'_> {
    fn accept_connection(&mut self, greeting: &str, handler: Box<dyn AuthorizationHandler>) {
        *self.authorization = Some(handler);
        let msg = if self.enable_apop && !self.apop_timestamp.is_empty() {
            format!("{greeting} {}", self.apop_timestamp)
        } else {
            greeting.to_string()
        };
        self.endpoint.send(&reply::ok(&msg));
    }

    fn reject_connection(&mut self, message: &str) {
        self.endpoint.send(&reply::err(message));
        self.endpoint.close();
    }
}

struct AuthView<'a> {
    endpoint: &'a mut dyn Endpoint,
    authorization: &'a mut Option<Box<dyn AuthorizationHandler>>,
    bundle: &'a Arc<Mutex<MailboxBundle>>,
    runtime: &'a Arc<Runtime>,
    control_handle: &'a Option<ConnHandle>,
    busy: &'a Arc<AtomicBool>,
    pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
    username: String,
    factory: Arc<dyn MailboxFactory>,
}

impl AuthenticateState for AuthView<'_> {
    fn proceed_open(&mut self, handler: Box<dyn TransactionHandler>) {
        let factory = Arc::clone(&self.factory);
        let user = self.username.clone();
        let bundle = Arc::clone(self.bundle);
        let busy = Arc::clone(self.busy);
        let pending_open = Arc::clone(self.pending_open);
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint
                .send(&reply::err("[SYS/TEMP] No connection handle"));
            return;
        };
        *self.pending_open.lock().unwrap() = Some(PendingOpen {
            handler,
            outcome: None,
        });
        self.busy.store(true, Ordering::Relaxed);
        self.endpoint.pause_read();
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut store = factory.create_store();
                store.open(&user).map_err(|e| e.to_string())?;
                let mb = store
                    .open_mailbox("INBOX", false)
                    .map_err(|e| e.to_string())?;
                Ok((store, mb))
            },
            move |result: Result<(Box<dyn MailboxStore>, Box<dyn Mailbox>), StorageError>| {
                handle.with_endpoint(move |ep| {
                    match result {
                        Ok((store, mb)) => {
                            {
                                let mut g = bundle.lock().unwrap();
                                g.store = Some(store);
                                g.mailbox = Some(mb);
                            }
                            if let Some(p) = pending_open.lock().unwrap().as_mut() {
                                p.outcome = Some(Ok(()));
                            }
                            ep.send(&reply::ok("Mailbox opened"));
                        }
                        Err(e) => {
                            if let Some(p) = pending_open.lock().unwrap().as_mut() {
                                p.outcome = Some(Err(()));
                            }
                            ep.send(&reply::err(&format!(
                                "[SYS/TEMP] Unable to open mailbox: {e}"
                            )));
                        }
                    }
                    busy.store(false, Ordering::Relaxed);
                    ep.resume_read();
                    // A command pipelined right behind PASS/APOP/AUTH (e.g.
                    // STAT) can be sitting in `cmd_queue` at this point —
                    // the client already sent it and is waiting on a reply,
                    // so nothing else will trigger another `receive()` to
                    // drain it without this (issue #181).
                    ep.poke_handler();
                });
            },
        );
    }

    fn accept_opened(
        &mut self,
        store: Box<dyn MailboxStore>,
        mailbox: Box<dyn Mailbox>,
        handler: Box<dyn TransactionHandler>,
    ) {
        {
            let mut g = self.bundle.lock().unwrap();
            g.store = Some(store);
            g.mailbox = Some(mailbox);
        }
        *self.pending_open.lock().unwrap() = Some(PendingOpen {
            handler,
            outcome: Some(Ok(())),
        });
        self.endpoint.send(&reply::ok("Mailbox opened"));
    }

    fn reject(&mut self, message: &str, handler: Box<dyn AuthorizationHandler>) {
        *self.authorization = Some(handler);
        self.endpoint.send(&reply::err(message));
    }

    fn reject_and_close(&mut self, message: &str) {
        self.endpoint.send(&reply::err(message));
        self.endpoint.close();
    }
}

struct StatusView<'a> {
    endpoint: &'a mut dyn Endpoint,
    transaction: &'a mut Option<Box<dyn TransactionHandler>>,
}

impl MailboxStatusState for StatusView<'_> {
    fn send_status(&mut self, count: u32, size: u64, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::ok(&format!("{count} {size}")));
    }

    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::err(message));
    }
}

struct ListView<'a> {
    endpoint: &'a mut dyn Endpoint,
    transaction: &'a mut Option<Box<dyn TransactionHandler>>,
    handle: ConnHandle,
    txn_slot: Arc<Mutex<Option<Box<dyn TransactionHandler>>>>,
}

impl ListState for ListView<'_> {
    fn begin_listing(&mut self, count: u32) -> Box<dyn ListWriter> {
        self.endpoint.send(&reply::ok(&format!("{count} messages")));
        Box::new(ListWriterImpl {
            handle: self.handle.clone(),
            lines: Vec::new(),
            txn_slot: Arc::clone(&self.txn_slot),
        })
    }

    fn send_listing(&mut self, number: u32, size: u64, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::ok(&format!("{number} {size}")));
    }

    fn no_such_message(&mut self, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::err("No such message"));
    }

    fn message_deleted(&mut self, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::err("Message deleted"));
    }

    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::err(message));
    }
}

struct ListWriterImpl {
    handle: ConnHandle,
    lines: Vec<Vec<u8>>,
    txn_slot: Arc<Mutex<Option<Box<dyn TransactionHandler>>>>,
}

impl ListWriter for ListWriterImpl {
    fn message(&mut self, number: u32, size: u64) {
        self.lines.push(reply::line(&format!("{number} {size}")));
    }

    fn end(self: Box<Self>, handler: Box<dyn TransactionHandler>) {
        let mut out = Vec::new();
        for line in &self.lines {
            out.extend_from_slice(line);
        }
        out.extend_from_slice(&reply::multiline_end());
        self.handle.send(out);
        *self.txn_slot.lock().unwrap() = Some(handler);
    }
}

struct RetrView<'a> {
    endpoint: &'a mut dyn Endpoint,
    control: &'a mut Pop3ControlHandler,
}

impl RetrieveState for RetrView<'_> {
    fn proceed_retr(&mut self, size: u64, handler: Box<dyn TransactionHandler>) {
        self.control.transaction = Some(handler);
        // Defer offload until mailbox is back in the bundle (see cmd_retr).
        self.control.pending_retr_offload = Some(size);
    }

    fn no_such_message(&mut self, handler: Box<dyn TransactionHandler>) {
        self.control.transaction = Some(handler);
        self.endpoint.send(&reply::err("No such message"));
    }

    fn message_deleted(&mut self, handler: Box<dyn TransactionHandler>) {
        self.control.transaction = Some(handler);
        self.endpoint.send(&reply::err("Message deleted"));
    }

    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>) {
        self.control.transaction = Some(handler);
        self.endpoint.send(&reply::err(message));
    }
}

struct DeleView<'a> {
    endpoint: &'a mut dyn Endpoint,
    transaction: &'a mut Option<Box<dyn TransactionHandler>>,
    metrics: &'a Arc<Pop3ServerMetrics>,
    otel: &'a Option<Arc<OtelPop3Metrics>>,
}

impl MarkDeletedState for DeleView<'_> {
    fn marked_deleted(&mut self, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        Pop3ServerMetrics::add(&self.metrics.dele, 1);
        if let Some(m) = self.otel {
            m.dele();
        }
        self.endpoint
            .send(&reply::ok("Message marked for deletion"));
    }

    fn no_such_message(&mut self, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::err("No such message"));
    }

    fn already_deleted(&mut self, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::err("Message already deleted"));
    }

    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::err(message));
    }
}

struct RsetView<'a> {
    endpoint: &'a mut dyn Endpoint,
    transaction: &'a mut Option<Box<dyn TransactionHandler>>,
}

impl ResetState for RsetView<'_> {
    fn reset_complete(&mut self, count: u32, size: u64, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::ok(&format!(
            "Mailbox reset, {count} messages ({size} octets)"
        )));
    }

    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::err(message));
    }
}

struct TopView<'a> {
    endpoint: &'a mut dyn Endpoint,
    control: &'a mut Pop3ControlHandler,
}

impl TopState for TopView<'_> {
    fn proceed_top(&mut self, lines: u32, handler: Box<dyn TransactionHandler>) {
        self.control.transaction = Some(handler);
        self.control.pending_top_offload = Some(lines);
    }

    fn no_such_message(&mut self, handler: Box<dyn TransactionHandler>) {
        self.control.transaction = Some(handler);
        self.endpoint.send(&reply::err("No such message"));
    }

    fn message_deleted(&mut self, handler: Box<dyn TransactionHandler>) {
        self.control.transaction = Some(handler);
        self.endpoint.send(&reply::err("Message deleted"));
    }

    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>) {
        self.control.transaction = Some(handler);
        self.endpoint.send(&reply::err(message));
    }
}

struct UidlView<'a> {
    endpoint: &'a mut dyn Endpoint,
    transaction: &'a mut Option<Box<dyn TransactionHandler>>,
    handle: ConnHandle,
    txn_slot: Arc<Mutex<Option<Box<dyn TransactionHandler>>>>,
}

impl UidlState for UidlView<'_> {
    fn begin_listing(&mut self) -> Box<dyn UidlWriter> {
        self.endpoint.send(&reply::ok("Unique-ID listing follows"));
        Box::new(UidlWriterImpl {
            handle: self.handle.clone(),
            lines: Vec::new(),
            txn_slot: Arc::clone(&self.txn_slot),
        })
    }

    fn send_uid(&mut self, number: u32, uid: &str, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::ok(&format!("{number} {uid}")));
    }

    fn no_such_message(&mut self, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::err("No such message"));
    }

    fn message_deleted(&mut self, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::err("Message deleted"));
    }

    fn error(&mut self, message: &str, handler: Box<dyn TransactionHandler>) {
        *self.transaction = Some(handler);
        self.endpoint.send(&reply::err(message));
    }
}

struct UidlWriterImpl {
    handle: ConnHandle,
    lines: Vec<Vec<u8>>,
    txn_slot: Arc<Mutex<Option<Box<dyn TransactionHandler>>>>,
}

impl UidlWriter for UidlWriterImpl {
    fn message(&mut self, number: u32, uid: &str) {
        self.lines.push(reply::line(&format!("{number} {uid}")));
    }

    fn end(self: Box<Self>, handler: Box<dyn TransactionHandler>) {
        let mut out = Vec::new();
        for line in &self.lines {
            out.extend_from_slice(line);
        }
        out.extend_from_slice(&reply::multiline_end());
        self.handle.send(out);
        *self.txn_slot.lock().unwrap() = Some(handler);
    }
}

struct QuitView<'a> {
    endpoint: &'a mut dyn Endpoint,
    control: &'a mut Pop3ControlHandler,
}

impl UpdateState for QuitView<'_> {
    fn proceed_quit(&mut self, _handler: Box<dyn TransactionHandler>) {
        self.control.start_quit_offload(self.endpoint);
    }

    fn error(&mut self, message: &str, _handler: Box<dyn TransactionHandler>) {
        self.endpoint.send(&reply::err(message));
        self.endpoint.close();
    }
}

/// RETR: pushes each chunk through [`crate::server::egress::Pop3DotStuffer`]
/// straight to `push` as it arrives — never buffers the message.
struct PushDotStuffer<F: FnMut(&[u8])> {
    push: F,
    stuffer: crate::server::egress::Pop3DotStuffer,
    out: Vec<u8>,
}

impl<F: FnMut(&[u8])> PushDotStuffer<F> {
    fn new(push: F) -> Self {
        Self {
            push,
            stuffer: crate::server::egress::Pop3DotStuffer::new(),
            out: Vec::new(),
        }
    }

    /// Flush the terminating `.\r\n` (and any trailing unterminated line).
    fn finish(&mut self) {
        self.out.clear();
        self.stuffer.finish(&mut self.out);
        if !self.out.is_empty() {
            (self.push)(&self.out);
        }
    }
}

impl<F: FnMut(&[u8])> hopf_mailbox::MessageReadCallback for PushDotStuffer<F> {
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        self.out.clear();
        self.stuffer.feed(chunk, &mut self.out);
        if !self.out.is_empty() {
            (self.push)(&self.out);
        }
        true
    }
}

/// TOP (RFC 1939 §7): headers plus the first `lines` body lines, dot-stuffed
/// and pushed straight to `push` as they're found — stops reading further
/// chunks entirely (via [`hopf_mailbox::MessageReadCallback::message_content`]
/// returning `false`) once the body-line budget is exhausted, so this never
/// reads — let alone holds in memory — the rest of a large message just to
/// discard it.
struct TopPushCallback<F: FnMut(&[u8])> {
    push: F,
    carry: Vec<u8>,
    in_body: bool,
    body_lines_left: u32,
    scratch: Vec<u8>,
}

impl<F: FnMut(&[u8])> TopPushCallback<F> {
    fn new(push: F, lines: u32) -> Self {
        Self {
            push,
            carry: Vec::new(),
            in_body: false,
            body_lines_left: lines,
            scratch: Vec::new(),
        }
    }

    /// Dot-stuff-and-push one already-terminator-stripped, bare-CR-stripped
    /// line.
    fn push_line(&mut self, line: &[u8]) {
        self.scratch.clear();
        if line.first() == Some(&b'.') {
            self.scratch.push(b'.');
        }
        self.scratch.extend_from_slice(line);
        self.scratch.extend_from_slice(b"\r\n");
        (self.push)(&self.scratch);
    }

    /// Process one raw (terminator-included) line; `false` once the body
    /// budget is exhausted.
    fn emit_line(&mut self, raw_line: &[u8]) -> bool {
        let mut end = raw_line.len();
        if end > 0 && raw_line[end - 1] == b'\n' {
            end -= 1;
        }
        if end > 0 && raw_line[end - 1] == b'\r' {
            end -= 1;
        }
        let mut line = raw_line[..end].to_vec();
        line.retain(|&b| b != b'\r');
        if !self.in_body {
            self.push_line(&line);
            if line.is_empty() {
                self.in_body = true;
            }
            true
        } else {
            if self.body_lines_left == 0 {
                return false;
            }
            self.push_line(&line);
            self.body_lines_left -= 1;
            true
        }
    }

    /// Flush any trailing unterminated line, then the dot-stuff terminator.
    fn finish(&mut self) {
        if !self.carry.is_empty() {
            let carry = std::mem::take(&mut self.carry);
            self.emit_line(&carry);
        }
        (self.push)(b".\r\n");
    }
}

impl<F: FnMut(&[u8])> hopf_mailbox::MessageReadCallback for TopPushCallback<F> {
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        self.carry.extend_from_slice(chunk);
        loop {
            let Some(nl) = self.carry.iter().position(|&b| b == b'\n') else {
                break;
            };
            let raw_line: Vec<u8> = self.carry.drain(..=nl).collect();
            if !self.emit_line(&raw_line) {
                return false;
            }
        }
        true
    }
}

/// Scan a message for any non-ASCII octet (RFC 6856 "UTF-8 string" content).
fn message_has_non_ascii(mb: &mut dyn Mailbox, message_number: u32) -> bool {
    struct Scan {
        found: bool,
    }
    impl MessageReadCallback for Scan {
        fn message_content(&mut self, chunk: &[u8]) -> bool {
            if chunk.iter().any(|b| !b.is_ascii()) {
                self.found = true;
                return false;
            }
            true
        }
    }
    let mut scan = Scan { found: false };
    match mb.read_message(message_number, &mut scan) {
        Ok(()) => scan.found,
        Err(_) => false,
    }
}

#[cfg(test)]
mod top_streaming_tests {
    use std::collections::BTreeSet;

    use hopf_mailbox::{AppendGuard, MailboxFactory};
    use tempfile::tempdir;

    use super::TopPushCallback;

    fn mailbox_with(msg: &[u8]) -> (tempfile::TempDir, Box<dyn hopf_mailbox::Mailbox>) {
        let dir = tempdir().unwrap();
        let factory = hopf_mailbox::MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("topuser").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        let mut guard = AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
        guard.append_content(msg).unwrap();
        guard.commit().unwrap();
        (dir, mb)
    }

    /// Drives the real production `TopPushCallback` (the same one
    /// `start_top_offload` uses), collecting its pushed chunks into a
    /// `Vec<u8>` for assertions — including the dot-stuff terminator.
    fn top_dot_stuffed(mb: &mut dyn hopf_mailbox::Mailbox, message_number: u32, lines: u32) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut cb = TopPushCallback::new(|bytes: &[u8]| out.extend_from_slice(bytes), lines);
            mb.read_message(message_number, &mut cb).unwrap();
            cb.finish();
        }
        out
    }

    #[test]
    fn matches_reference_truncation_plus_dot_stuff() {
        let msg = b"From: a@b\r\nSubject: x\r\n\r\nbody1\r\nbody2\r\nbody3\r\n";
        let (_dir, mut mb) = mailbox_with(msg);
        let top = top_dot_stuffed(mb.as_mut(), 1, 1);
        assert_eq!(top, b"From: a@b\r\nSubject: x\r\n\r\nbody1\r\n.\r\n".to_vec());
    }

    #[test]
    fn zero_lines_returns_headers_only() {
        let msg = b"From: a@b\r\nSubject: x\r\n\r\nbody1\r\nbody2\r\n";
        let (_dir, mut mb) = mailbox_with(msg);
        let top = top_dot_stuffed(mb.as_mut(), 1, 0);
        assert_eq!(top, b"From: a@b\r\nSubject: x\r\n\r\n.\r\n".to_vec());
    }

    #[test]
    fn lines_beyond_message_length_returns_whole_body() {
        let msg = b"Subject: x\r\n\r\nonly-line\r\n";
        let (_dir, mut mb) = mailbox_with(msg);
        let top = top_dot_stuffed(mb.as_mut(), 1, 100);
        assert_eq!(top, b"Subject: x\r\n\r\nonly-line\r\n.\r\n".to_vec());
    }

    #[test]
    fn handles_message_with_no_trailing_newline() {
        let msg = b"Subject: x\r\n\r\nbody1\r\nbody2-no-trailing-newline";
        let (_dir, mut mb) = mailbox_with(msg);
        let top = top_dot_stuffed(mb.as_mut(), 1, 5);
        assert_eq!(
            top,
            b"Subject: x\r\n\r\nbody1\r\nbody2-no-trailing-newline\r\n.\r\n".to_vec()
        );
    }

    #[test]
    fn doubles_a_leading_dot_in_a_body_line() {
        let msg = b"Subject: x\r\n\r\n.leading dot\r\nplain\r\n";
        let (_dir, mut mb) = mailbox_with(msg);
        let top = top_dot_stuffed(mb.as_mut(), 1, 2);
        assert_eq!(
            top,
            b"Subject: x\r\n\r\n..leading dot\r\nplain\r\n.\r\n".to_vec()
        );
    }

    #[test]
    fn stops_reading_further_chunks_once_line_budget_hit() {
        // A callback that records how many message_content calls it saw
        // *after* the budget-exhausted false return would require peeking
        // at read_message's internals; instead assert indirectly: pushed
        // output never contains body content past the requested line
        // count, for a message much larger than the requested budget.
        let mut msg = b"Subject: x\r\n\r\n".to_vec();
        for i in 0..1000 {
            msg.extend_from_slice(format!("line{i}\r\n").as_bytes());
        }
        let (_dir, mut mb) = mailbox_with(&msg);
        let top = top_dot_stuffed(mb.as_mut(), 1, 3);
        assert_eq!(
            top,
            b"Subject: x\r\n\r\nline0\r\nline1\r\nline2\r\n.\r\n".to_vec()
        );
    }
}

#[cfg(test)]
mod utf8_scan_tests {
    use std::collections::BTreeSet;

    use hopf_mailbox::{AppendGuard, MailboxFactory};
    use tempfile::tempdir;

    use super::message_has_non_ascii;

    fn mailbox_with(msg: &[u8]) -> (tempfile::TempDir, Box<dyn hopf_mailbox::Mailbox>) {
        let dir = tempdir().unwrap();
        let factory = hopf_mailbox::MaildirFactory::new(dir.path());
        let mut store = factory.create_store();
        store.open("utf8user").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        let mut guard = AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
        guard.append_content(msg).unwrap();
        guard.commit().unwrap();
        (dir, mb)
    }

    #[test]
    fn ascii_only_does_not_require_utf8() {
        let (_dir, mut mb) = mailbox_with(b"Subject: hello\r\n\r\nbody\r\n");
        assert!(!message_has_non_ascii(mb.as_mut(), 1));
    }

    #[test]
    fn non_ascii_header_requires_utf8() {
        let (_dir, mut mb) = mailbox_with("Subject: café\r\n\r\nbody\r\n".as_bytes());
        assert!(message_has_non_ascii(mb.as_mut(), 1));
    }
}

#[cfg(test)]
mod telemetry_tests {
    use super::*;
    use hopf_auth::PasswordStore;
    use hopf_core::{Runtime, RuntimeConfig};
    use hopf_mailbox::MaildirFactory;
    use hopf_otel::{OtelConfig, SpanContext, TelemetryPipeline};
    use crate::server::handler::Pop3HandlerFactory;

    #[test]
    fn with_telemetry_sets_parseable_traceparent_on_connect() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-pop3-tp-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let root = tempfile::tempdir().unwrap();
        let cfg = OtelConfig::new("pop3-tp-test")
            .with_jsonl_traces(&dir)
            .with_jsonl_metrics(&dir);
        let pipeline = TelemetryPipeline::start(cfg).unwrap();
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let store = Arc::new(PasswordStore::new().with_user("u", "p"));
        let factory = Arc::new(MaildirFactory::new(root.path()));
        let listen: SocketAddr = "127.0.0.1:1110".parse().unwrap();
        let config = Pop3Config::new(listen, "localhost", store, factory);
        let app = DefaultPop3HandlerFactory::new("ready").create();
        let mut h = Pop3ControlHandler::new(
            app,
            Pop3ServerMetrics::shared(),
            config,
            rt,
        )
        .with_telemetry(
            Some(pipeline.pop3_metrics()),
            Some(pipeline.export_handle()),
            true,
        );
        h.begin_connection_telemetry();
        let tp = h.meta.traceparent.clone().expect("traceparent set");
        let ctx = SpanContext::from_traceparent(&tp).expect("valid traceparent");
        assert!(!ctx.trace_id.iter().all(|&b| b == 0));

        let xfer = h
            .begin_retrieve_telemetry("retr", 10)
            .expect("retrieve telemetry");
        let xfer_tp = h.meta.traceparent.clone().expect("xfer traceparent");
        let xfer_ctx = SpanContext::from_traceparent(&xfer_tp).unwrap();
        assert_eq!(xfer_ctx.trace_id, ctx.trace_id);
        assert_ne!(xfer_ctx.span_id, ctx.span_id);
        xfer.finish(true);

        h.end_connection_telemetry();
        assert!(h.meta.traceparent.is_none());
        pipeline.shutdown();
        let _ = std::fs::remove_file(&dir);
    }
}
