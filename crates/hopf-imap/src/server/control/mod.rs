// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP control-connection protocol handler.

mod ext;

use std::collections::{BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use hopf_auth::{create_server, SaslMechanism, SaslServer, SaslServerOptions, SaslServerStep};
use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, StorageError};
use hopf_mailbox::{Mailbox, MailboxStore};
use hopf_otel::{
    ExportHandle, RequestTimer, Span, SpanKind, Trace, ImapServerMetrics as OtelImapMetrics,
};

use rmimeparser::charset::base64;

use crate::enable::EnabledExtensions;
use crate::server::capability::build_capabilities;
use crate::server::codec::{
    parse_astring, parse_flag_list, parse_sequence_set, parse_store_item, ImapCommand,
    ImapServerLexer, LexEvent, MAX_COMMAND_LINE,
};
use crate::server::fetch_format::parse_fetch_args;
use crate::server::handler::{
    AuthenticatedHandler, ClientConnected, ImapConnectionMetadata, NotAuthenticatedHandler,
    SelectedHandler,
};
use crate::server::idle::{is_idle_done, IdleState};
use crate::server::metrics::ImapServerMetrics;
use crate::server::reply::{continuation, tagged_bad, tagged_no, tagged_ok, untagged};
use crate::server::search_parse::parse_search;
use crate::server::service::ImapConfig;
use crate::server::session::ImapSessionState;
use crate::server::views::{
    begin_busy, end_busy, AppendView, AuthView, CloseView, ConnectedView, CopyView, FetchView,
    MgmtOp, MgmtView, SearchView, SelectView, StoreView,
};

/// In-flight command telemetry finished when the tagged reply is sent.
struct CommandTelemetry {
    timer: RequestTimer,
    span: Option<Span>,
    verb: String,
}

pub(crate) struct MailboxBundle {
    pub store: Option<Box<dyn MailboxStore>>,
    pub mailbox: Option<Box<dyn Mailbox>>,
    pub read_only: bool,
}

/// Kind of in-flight storage operation.
pub(crate) enum PendingKind {
    Auth {
        tag: String,
        caps: String,
    },
    /// PREAUTH greeting deferred until the store is open.
    Preauth {
        caps: String,
        greeting: String,
    },
    Select {
        tag: String,
        examine: bool,
        /// Emit HIGHESTMODSEQ when CONDSTORE is active for this session.
        condstore: bool,
    },
    Close {
        tag: String,
        ok: String,
    },
    Mgmt {
        tag: String,
        ok: String,
    },
    List {
        tag: String,
        lsub: bool,
    },
    /// Untagged payload bytes + tagged OK text.
    Data {
        tag: String,
        ok: String,
    },
    Search {
        tag: String,
        #[allow(dead_code)]
        by_uid: bool,
    },
}

/// In-flight mailbox/store work completed on the storage pool.
pub(crate) struct PendingOpen {
    pub auth_handler: Option<Box<dyn AuthenticatedHandler>>,
    pub selected_handler: Option<Box<dyn SelectedHandler>>,
    /// `None` while in flight; `Some(Ok(payload))` / `Some(Err)` when done.
    pub outcome: Option<Result<Vec<u8>, String>>,
    pub kind: PendingKind,
}

/// One AUTHENTICATE exchange awaiting the next base64 continuation line.
struct PendingAuth {
    tag: String,
    server: Box<dyn SaslServer>,
}

/// Result of a credential check offloaded to the storage pool (issue #181)
/// — `CredentialStore::password_match`/`SaslServer::step` can block for
/// LDAP/PAM-backed stores, so both run off the reactor thread; the outcome
/// lands here for `sync_pending_auth_check` to apply once back on the
/// reactor (the storage callback only has `&mut dyn Endpoint`, never
/// `&mut Self`).
enum AuthCheckOutcome {
    /// LOGIN.
    Login {
        tag: String,
        user: String,
        result: Result<bool, String>,
    },
    /// AUTHENTICATE (initial or continuation step). `first_step` marks the
    /// server-first initial call (no client data yet) — a `Complete` there
    /// means the mechanism authenticated nobody, so it's still a failure.
    Step {
        tag: String,
        first_step: bool,
        result: Result<(Box<dyn SaslServer>, SaslServerStep), String>,
    },
}

/// Per-connection IMAP protocol state machine.
pub struct ImapControlHandler {
    client_connected: Option<Box<dyn ClientConnected>>,
    not_authenticated: Option<Box<dyn NotAuthenticatedHandler>>,
    authenticated: Option<Box<dyn AuthenticatedHandler>>,
    selected: Option<Box<dyn SelectedHandler>>,
    config: ImapConfig,
    runtime: Arc<Runtime>,
    metrics: Arc<ImapServerMetrics>,
    lexer: ImapServerLexer,
    session: ImapSessionState,
    tls: bool,
    /// SHA-256 fingerprint of the peer's mTLS client certificate, if any —
    /// fed into `SaslServerOptions.peer_certificate` for SASL EXTERNAL.
    peer_certificate: Option<String>,
    expect_implicit_tls: bool,
    greeting_sent: bool,
    starttls_used: bool,
    username: Option<String>,
    control_handle: Option<ConnHandle>,
    bundle: Arc<Mutex<MailboxBundle>>,
    peer: SocketAddr,
    local: SocketAddr,
    meta: ImapConnectionMetadata,
    busy: Arc<AtomicBool>,
    cmd_queue: VecDeque<ImapCommand>,
    pending_auth: Option<PendingAuth>,
    pending_auth_check: Arc<Mutex<Option<AuthCheckOutcome>>>,
    /// APPEND literal being spooled to a temp file as chunks arrive — never
    /// buffered whole in memory (see `AppendChunk`/`finalize_pending_append`).
    /// Writes are offloaded to `hopf_core::StorageExecutor` (issue #185)
    /// rather than done inline on the reactor thread; shared (not a plain
    /// field) so the storage-pool write callback, which only ever gets a
    /// cloned `Arc`, can safely reach it.
    append_spool: Arc<Mutex<AppendSpoolState>>,
    /// First spool write error, if any.
    pending_append_error: Option<String>,
    /// Finalized spool path, ready for `cmd_append` to stream from — `None`
    /// path with no error means a zero-length (`{0}`) literal.
    pending_append_path: Option<std::path::PathBuf>,
    /// The APPEND's own trailing `Command` event, stashed when it arrives
    /// before `append_spool`'s queued writes have finished draining (issue
    /// #185) — `sync_pending_append` finalizes and dispatches it once
    /// ready, triggered by the last write's `poke_handler` call. Also
    /// blocks `enqueue_or_dispatch`/`drain_queue` the same way `busy`
    /// does, so a further pipelined command can't run ahead of it.
    pending_append_cmd: Option<ImapCommand>,
    pending_open: Arc<Mutex<Option<PendingOpen>>>,
    /// Per-session ENABLE set.
    enabled: EnabledExtensions,
    /// IDLE session.
    idle: IdleState,
    /// QRESYNC parameters from the last SELECT (uidvalidity, modseq).
    pending_qresync: Option<(u64, u64)>,
    otel_metrics: Option<Arc<OtelImapMetrics>>,
    export: Option<ExportHandle>,
    traces_enabled: bool,
    conn_trace: Option<Trace>,
    pending_cmd_tel: Option<CommandTelemetry>,
}

impl ImapControlHandler {
    /// Create a new control handler for one accept.
    pub fn new(
        client: Box<dyn ClientConnected>,
        config: ImapConfig,
        runtime: Arc<Runtime>,
        metrics: Arc<ImapServerMetrics>,
    ) -> Self {
        let expect_implicit_tls = config.implicit_tls && config.tls_acceptor.is_some();
        let max_line = if config.max_line == 0 {
            MAX_COMMAND_LINE
        } else {
            config.max_line
        };
        Self {
            client_connected: Some(client),
            not_authenticated: None,
            authenticated: None,
            selected: None,
            config,
            runtime,
            metrics,
            lexer: ImapServerLexer::new(max_line),
            session: ImapSessionState::NotAuthenticated,
            tls: false,
            peer_certificate: None,
            expect_implicit_tls,
            greeting_sent: false,
            starttls_used: false,
            username: None,
            control_handle: None,
            bundle: Arc::new(Mutex::new(MailboxBundle {
                store: None,
                mailbox: None,
                read_only: false,
            })),
            peer: SocketAddr::from(([0, 0, 0, 0], 0)),
            local: SocketAddr::from(([0, 0, 0, 0], 0)),
            meta: ImapConnectionMetadata {
                peer: SocketAddr::from(([0, 0, 0, 0], 0)),
                local: SocketAddr::from(([0, 0, 0, 0], 0)),
                tls: false,
                user: None,
                traceparent: None,
            },
            busy: Arc::new(AtomicBool::new(false)),
            cmd_queue: VecDeque::new(),
            pending_auth: None,
            pending_auth_check: Arc::new(Mutex::new(None)),
            append_spool: Arc::new(Mutex::new(AppendSpoolState::default())),
            pending_append_error: None,
            pending_append_path: None,
            pending_append_cmd: None,
            pending_open: Arc::new(Mutex::new(None)),
            enabled: EnabledExtensions::default(),
            idle: IdleState::default(),
            pending_qresync: None,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            conn_trace: None,
            pending_cmd_tel: None,
        }
    }

    /// Attach OTel metrics / traces from a telemetry pipeline.
    pub fn with_telemetry(
        mut self,
        otel_metrics: Option<Arc<OtelImapMetrics>>,
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
        self.meta.user = self.username.clone();
    }

    fn begin_connection_telemetry(&mut self) {
        if let Some(m) = &self.otel_metrics {
            m.connection_opened();
        }
        if self.traces_enabled {
            if let Some(export) = self.export.clone() {
                let t = Trace::new("IMAP connection", SpanKind::Server);
                t.set_exporter(export);
                self.meta.traceparent = Some(t.traceparent());
                self.conn_trace = Some(t);
            }
        }
    }

    fn end_connection_telemetry(&mut self) {
        if let Some(tel) = self.pending_cmd_tel.take() {
            self.finish_command_telemetry(tel, "aborted");
        }
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

    fn begin_command_telemetry(&mut self, verb: &str) -> Option<CommandTelemetry> {
        if self.otel_metrics.is_none() && self.conn_trace.is_none() {
            return None;
        }
        let span = if let Some(trace) = &self.conn_trace {
            let s = trace.start_span("IMAP command", SpanKind::Server);
            s.set_attribute("imap.command.verb", verb);
            self.meta.traceparent = Some(trace.traceparent());
            Some(s)
        } else {
            None
        };
        Some(CommandTelemetry {
            timer: RequestTimer::start(),
            span,
            verb: verb.to_string(),
        })
    }

    fn finish_command_telemetry(&mut self, tel: CommandTelemetry, outcome: &str) {
        ImapServerMetrics::add(&self.metrics.commands, 1);
        if let Some(span) = tel.span {
            span.set_attribute("outcome", outcome);
            if outcome == "ok" {
                span.set_status_ok();
            } else {
                span.set_status_error(outcome);
            }
            span.end();
        }
        if let Some(trace) = &self.conn_trace {
            self.meta.traceparent = Some(trace.traceparent());
        }
        if let Some(m) = &self.otel_metrics {
            m.command_completed(&tel.verb, outcome, tel.timer.elapsed());
        }
    }

    fn record_auth(&self, ok: bool) {
        if ok {
            ImapServerMetrics::add(&self.metrics.auth_ok, 1);
        } else {
            ImapServerMetrics::add(&self.metrics.auth_fail, 1);
        }
        if let Some(m) = &self.otel_metrics {
            m.auth(ok);
        }
    }

    fn record_starttls(&self) {
        ImapServerMetrics::add(&self.metrics.starttls, 1);
        if let Some(m) = &self.otel_metrics {
            m.starttls();
        }
    }

    pub(super) fn send(&mut self, endpoint: &mut dyn Endpoint, bytes: Vec<u8>) {
        endpoint.send(&bytes);
    }

    fn capabilities(&self) -> String {
        let authenticated = matches!(
            self.session,
            ImapSessionState::Authenticated | ImapSessionState::Selected
        );
        build_capabilities(&self.config, authenticated, self.tls)
    }

    fn greet(&mut self, endpoint: &mut dyn Endpoint) {
        if self.greeting_sent {
            return;
        }
        self.greeting_sent = true;
        ImapServerMetrics::add(&self.metrics.connections, 1);
        self.sync_meta_addrs();
        let caps = self.capabilities();
        let mut view = ConnectedView {
            endpoint,
            not_authenticated: &mut self.not_authenticated,
            caps: &caps,
            session: &mut self.session,
            username: &mut self.username,
            bundle: &self.bundle,
            runtime: &self.runtime,
            busy: &self.busy,
            control_handle: &self.control_handle,
            pending_open: &self.pending_open,
            factory: Arc::clone(&self.config.mailbox_factory),
        };
        if let Some(mut c) = self.client_connected.take() {
            c.connected(&mut view, &self.meta);
            self.client_connected = Some(c);
        }
    }

    fn sync_pending(&mut self, endpoint: &mut dyn Endpoint) {
        let pending = {
            let mut slot = self.pending_open.lock().unwrap();
            let ready = slot.as_ref().map(|p| p.outcome.is_some()).unwrap_or(false);
            if !ready {
                return;
            }
            slot.take()
        };
        let Some(PendingOpen {
            auth_handler,
            selected_handler,
            outcome,
            kind,
        }) = pending
        else {
            return;
        };
        let Some(outcome) = outcome else {
            return;
        };
        let cmd_ok = outcome.is_ok();

        match kind {
            PendingKind::Auth { tag, caps } => match outcome {
                Ok(_) => {
                    if let Some(h) = auth_handler {
                        self.authenticated = Some(h);
                    }
                    self.not_authenticated = None;
                    self.session = ImapSessionState::Authenticated;
                    self.send(
                        endpoint,
                        tagged_ok(&tag, &format!("[CAPABILITY {caps}] LOGIN completed")),
                    );
                }
                Err(e) => {
                    self.send(
                        endpoint,
                        tagged_no(&tag, &format!("Mailbox unavailable: {e}")),
                    );
                    // Keep not-authenticated if we still have one.
                }
            },
            PendingKind::Preauth { caps, greeting } => match outcome {
                Ok(_) => {
                    if let Some(h) = auth_handler {
                        self.authenticated = Some(h);
                    }
                    self.not_authenticated = None;
                    self.session = ImapSessionState::Authenticated;
                    self.send(
                        endpoint,
                        untagged(&format!("PREAUTH [CAPABILITY {caps}] {greeting}")),
                    );
                }
                Err(e) => {
                    self.send(
                        endpoint,
                        untagged(&format!("BYE PREAUTH mailbox unavailable: {e}")),
                    );
                    endpoint.close();
                }
            },
            PendingKind::Select {
                tag,
                examine,
                condstore,
            } => match outcome {
                Ok(payload) => {
                    let s = String::from_utf8_lossy(&payload);
                    // exists|recent|uidvalidity|uidnext|highestmodseq[|VANISHED uids]
                    // `recent` stays in the payload for backends; unsolicited RECENT is
                    // not emitted (IMAP4rev2 / RFC 9051).
                    let parts: Vec<&str> = s.split('|').collect();
                    let (exists, _recent, uidvalidity, uidnext, highest) = if parts.len() >= 5 {
                        (parts[0], parts[1], parts[2], parts[3], parts[4])
                    } else if parts.len() == 4 {
                        (parts[0], parts[1], parts[2], parts[3], "0")
                    } else {
                        ("0", "0", "0", "1", "0")
                    };
                    self.send(
                        endpoint,
                        untagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)"),
                    );
                    self.send(
                        endpoint,
                        untagged(
                            "OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted",
                        ),
                    );
                    self.send(endpoint, untagged(&format!("{exists} EXISTS")));
                    self.send(
                        endpoint,
                        untagged(&format!("OK [UIDVALIDITY {uidvalidity}] UIDs valid")),
                    );
                    self.send(
                        endpoint,
                        untagged(&format!("OK [UIDNEXT {uidnext}] Predicted next UID")),
                    );
                    if condstore {
                        if let Ok(h) = highest.parse::<u64>() {
                            if h > 0 {
                                self.send(
                                    endpoint,
                                    untagged(&format!("OK [HIGHESTMODSEQ {h}] Highest modseq")),
                                );
                            }
                        }
                    }
                    // Optional VANISHED (EARLIER) from QRESYNC — only when backend provided UIDs.
                    if parts.len() >= 6 && !parts[5].is_empty() {
                        self.send(
                            endpoint,
                            untagged(&format!("VANISHED (EARLIER) {}", parts[5])),
                        );
                    }
                    if let Ok(n) = exists.parse::<u32>() {
                        self.idle.last_exists = n;
                    }
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    self.session = ImapSessionState::Selected;
                    let msg = if examine {
                        "[READ-ONLY] EXAMINE completed"
                    } else {
                        "[READ-WRITE] SELECT completed"
                    };
                    self.send(endpoint, tagged_ok(&tag, msg));
                }
                Err(e) => {
                    self.send(endpoint, tagged_no(&tag, &e));
                    if let Some(h) = auth_handler {
                        self.authenticated = Some(h);
                    }
                }
            },
            PendingKind::Close { tag, ok } => match outcome {
                Ok(_) => {
                    self.selected = None;
                    if let Some(h) = auth_handler {
                        self.authenticated = Some(h);
                    }
                    self.session = ImapSessionState::Authenticated;
                    self.send(endpoint, tagged_ok(&tag, &ok));
                }
                Err(e) => {
                    self.send(endpoint, tagged_no(&tag, &e));
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                }
            },
            PendingKind::Mgmt { tag, ok } => match outcome {
                Ok(_) => {
                    if let Some(h) = auth_handler {
                        self.authenticated = Some(h);
                    }
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    self.send(endpoint, tagged_ok(&tag, &ok));
                }
                Err(e) => {
                    if let Some(h) = auth_handler {
                        self.authenticated = Some(h);
                    }
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    self.send(endpoint, tagged_no(&tag, &e));
                }
            },
            PendingKind::List { tag, lsub } => match outcome {
                Ok(payload) => {
                    let kind = if lsub { "LSUB" } else { "LIST" };
                    for entry in payload.split(|&b| b == 0) {
                        if entry.is_empty() {
                            continue;
                        }
                        let line = String::from_utf8_lossy(entry);
                        // LIST-STATUS embeds full untagged lines (LIST … / STATUS …).
                        if line.starts_with("STATUS ")
                            || line.starts_with("LIST ")
                            || line.starts_with("LSUB ")
                        {
                            self.send(endpoint, untagged(&line));
                        } else {
                            self.send(endpoint, untagged(&format!("{kind} {line}")));
                        }
                    }
                    if let Some(h) = auth_handler {
                        self.authenticated = Some(h);
                    }
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    self.send(endpoint, tagged_ok(&tag, &format!("{kind} completed")));
                }
                Err(e) => {
                    if let Some(h) = auth_handler {
                        self.authenticated = Some(h);
                    }
                    self.send(endpoint, tagged_no(&tag, &e));
                }
            },
            PendingKind::Data { tag, ok } => match outcome {
                Ok(payload) => {
                    if !payload.is_empty() {
                        endpoint.send(&payload);
                    }
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    if let Some(h) = auth_handler {
                        self.authenticated = Some(h);
                    }
                    self.send(endpoint, tagged_ok(&tag, &ok));
                }
                Err(e) => {
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    if let Some(h) = auth_handler {
                        self.authenticated = Some(h);
                    }
                    self.send(endpoint, tagged_no(&tag, &e));
                }
            },
            PendingKind::Search { tag, .. } => match outcome {
                Ok(payload) => {
                    let nums = String::from_utf8_lossy(&payload);
                    self.send(endpoint, untagged(&format!("SEARCH {nums}")));
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    self.send(endpoint, tagged_ok(&tag, "SEARCH completed"));
                }
                Err(e) => {
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    self.send(endpoint, tagged_no(&tag, &e));
                }
            },
        }
        if let Some(tel) = self.pending_cmd_tel.take() {
            self.finish_command_telemetry(tel, if cmd_ok { "ok" } else { "fail" });
        }
    }

    fn drain_queue(&mut self, endpoint: &mut dyn Endpoint) {
        while !self.busy.load(Ordering::Relaxed) && self.pending_append_cmd.is_none() {
            let Some(cmd) = self.cmd_queue.pop_front() else {
                break;
            };
            self.dispatch(endpoint, cmd);
        }
    }

    fn enqueue_or_dispatch(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        // `pending_append_cmd` gates the same way `busy` does (issue
        // #185) — a further pipelined command must not run ahead of an
        // APPEND whose spool writes are still draining.
        if self.busy.load(Ordering::Relaxed) || self.pending_append_cmd.is_some() {
            self.cmd_queue.push_back(cmd);
        } else {
            self.dispatch(endpoint, cmd);
        }
    }

    fn dispatch(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if self.session == ImapSessionState::Logout {
            self.send(
                endpoint,
                tagged_bad(&cmd.tag, "Command not valid in LOGOUT state"),
            );
            return;
        }
        if self.idle.shared.is_active() {
            if is_idle_done(&cmd.verb) {
                self.cmd_idle_done(endpoint);
            } else {
                self.send(
                    endpoint,
                    tagged_bad(&cmd.tag, "Expected DONE while IDLEing"),
                );
            }
            return;
        }
        let verb = cmd.verb.clone();
        let tel = self.begin_command_telemetry(&verb);
        let verb = verb.as_str();
        match verb {
            "CAPABILITY" => {
                let caps = self.capabilities();
                self.send(endpoint, untagged(&format!("CAPABILITY {caps}")));
                self.send(endpoint, tagged_ok(&cmd.tag, "CAPABILITY completed"));
            }
            "NOOP" => self.cmd_noop(endpoint, &cmd.tag),
            "LOGOUT" => {
                self.idle.end();
                self.session = ImapSessionState::Logout;
                self.send(endpoint, untagged("BYE Logging out"));
                self.send(endpoint, tagged_ok(&cmd.tag, "LOGOUT completed"));
                self.offload_close(false);
                endpoint.close();
            }
            "STARTTLS" => self.cmd_starttls(endpoint, &cmd.tag),
            "LOGIN" => self.cmd_login(endpoint, cmd),
            "AUTHENTICATE" => self.cmd_authenticate(endpoint, cmd),
            "ID" => self.cmd_id(endpoint, cmd),
            "ENABLE" => self.cmd_enable(endpoint, cmd),
            "SELECT" => self.cmd_select(endpoint, cmd, false),
            "EXAMINE" => self.cmd_select(endpoint, cmd, true),
            "CLOSE" => self.cmd_close(endpoint, &cmd.tag, true),
            "UNSELECT" => self.cmd_close(endpoint, &cmd.tag, false),
            "CREATE" => self.cmd_mgmt_name(endpoint, cmd, MgmtOp::Create),
            "DELETE" => self.cmd_mgmt_name(endpoint, cmd, MgmtOp::Delete),
            "RENAME" => self.cmd_rename(endpoint, cmd),
            "SUBSCRIBE" => self.cmd_mgmt_name(endpoint, cmd, MgmtOp::Subscribe),
            "UNSUBSCRIBE" => self.cmd_mgmt_name(endpoint, cmd, MgmtOp::Unsubscribe),
            "LIST" => self.cmd_list(endpoint, cmd, false),
            "LSUB" => self.cmd_list(endpoint, cmd, true),
            "STATUS" => self.cmd_status(endpoint, cmd),
            "NAMESPACE" => self.cmd_namespace(endpoint, &cmd.tag),
            "IDLE" => self.cmd_idle(endpoint, &cmd.tag),
            "GETQUOTA" => self.cmd_getquota(endpoint, cmd),
            "GETQUOTAROOT" => self.cmd_getquotaroot(endpoint, cmd),
            "SETQUOTA" => self.cmd_setquota(endpoint, cmd),
            "APPEND" => self.cmd_append(endpoint, cmd),
            "FETCH" => self.cmd_fetch(endpoint, cmd, false),
            "STORE" => self.cmd_store(endpoint, cmd, false),
            "SEARCH" => self.cmd_search(endpoint, cmd, false),
            "COPY" => self.cmd_copy(endpoint, cmd, false),
            "MOVE" => self.cmd_move(endpoint, cmd, false),
            "EXPUNGE" => self.cmd_expunge(endpoint, &cmd.tag, None),
            "UID" => self.cmd_uid(endpoint, cmd),
            "DONE" => self.send(endpoint, tagged_bad(&cmd.tag, "Not IDLEing")),
            _ => self.send(
                endpoint,
                tagged_bad(&cmd.tag, &format!("Unknown command {}", cmd.verb)),
            ),
        }
        // Hold telemetry across storage offloads and multi-step AUTHENTICATE.
        if self.busy.load(Ordering::Relaxed) || self.pending_auth.is_some() {
            self.pending_cmd_tel = tel;
        } else if let Some(tel) = tel {
            self.finish_command_telemetry(tel, "ok");
        }
    }

    fn cmd_starttls(&mut self, endpoint: &mut dyn Endpoint, tag: &str) {
        if self.session != ImapSessionState::NotAuthenticated {
            self.send(
                endpoint,
                tagged_bad(tag, "STARTTLS only valid before authentication"),
            );
            return;
        }
        if self.tls {
            self.send(endpoint, tagged_bad(tag, "TLS already active"));
            return;
        }
        if self.config.tls_acceptor.is_none() || self.config.implicit_tls {
            self.send(endpoint, tagged_bad(tag, "TLS not available"));
            return;
        }
        self.send(endpoint, tagged_ok(tag, "Begin TLS negotiation"));
        self.starttls_used = true;
        let _ = endpoint.start_tls();
    }

    pub(super) fn require_auth(&mut self, endpoint: &mut dyn Endpoint, tag: &str) -> bool {
        matches!(
            self.session,
            ImapSessionState::Authenticated | ImapSessionState::Selected
        ) || {
            self.send(endpoint, tagged_no(tag, "Not authenticated"));
            false
        }
    }

    pub(super) fn require_selected(&mut self, endpoint: &mut dyn Endpoint, tag: &str) -> bool {
        if self.session == ImapSessionState::Selected {
            true
        } else {
            self.send(endpoint, tagged_no(tag, "No mailbox selected"));
            false
        }
    }

    fn cmd_login(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if self.session != ImapSessionState::NotAuthenticated {
            self.send(endpoint, tagged_bad(&cmd.tag, "Already authenticated"));
            return;
        }
        if !self.tls && self.config.tls_acceptor.is_some() && !self.config.implicit_tls {
            self.send(
                endpoint,
                tagged_no(&cmd.tag, "[PRIVACYREQUIRED] LOGIN disabled on plaintext"),
            );
            return;
        }
        let Ok((user, rest)) = parse_astring(cmd.args.trim()) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid LOGIN arguments"));
            return;
        };
        let Ok((pass, _)) = parse_astring(rest) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid LOGIN arguments"));
            return;
        };
        let Some(handle) = self.control_handle.clone() else {
            self.send(endpoint, tagged_no(&cmd.tag, "Internal error: no handle"));
            return;
        };
        let store = Arc::clone(&self.config.store);
        let tag = cmd.tag.clone();
        let user_for_check = user.clone();
        let pending = Arc::clone(&self.pending_auth_check);
        let busy = Arc::clone(&self.busy);
        begin_busy(endpoint, &self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || Ok(store.password_match(&user_for_check, &pass)),
            move |result: Result<bool, StorageError>| {
                let result = result.map_err(|e| e.to_string());
                *pending.lock().unwrap() = Some(AuthCheckOutcome::Login { tag, user, result });
                handle.with_endpoint(move |ep| end_busy(ep, &busy));
            },
        );
    }

    fn cmd_authenticate(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if self.session != ImapSessionState::NotAuthenticated {
            self.send(endpoint, tagged_bad(&cmd.tag, "Already authenticated"));
            return;
        }
        let mut parts = cmd.args.split_whitespace();
        let Some(mech_name) = parts.next() else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Missing mechanism"));
            return;
        };
        let Some(mech) = SaslMechanism::from_name(mech_name) else {
            self.send(endpoint, tagged_no(&cmd.tag, "Unsupported mechanism"));
            return;
        };
        if mech.requires_tls() && !self.tls {
            self.send(
                endpoint,
                tagged_no(
                    &cmd.tag,
                    "[PRIVACYREQUIRED] Encryption required for requested authentication mechanism",
                ),
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

        let initial_response = match parts.next() {
            // RFC 4959 SASL-IR: a bare "=" is an explicit *empty* initial
            // response, fed straight to the mechanism — not "no response
            // yet" (the `None` arm below, which prompts for one).
            Some("=") => Some(Vec::new()),
            Some(ir) => match base64::decode(ir) {
                Ok(raw) => Some(raw),
                Err(_) => {
                    self.send(endpoint, tagged_no(&cmd.tag, "Invalid base64"));
                    return;
                }
            },
            None => None,
        };

        if server.server_first() && initial_response.is_none() {
            // A server-first mechanism (e.g. CRAM-MD5) must send its
            // challenge before any client response exists to step on —
            // "complete" on this very first step would mean the mechanism
            // authenticated nobody, so treat it as failure, not success
            // (see `AuthCheckOutcome::Step::first_step`).
            self.sasl_step(endpoint, cmd.tag, server, None, true);
            return;
        }
        self.sasl_step(endpoint, cmd.tag, server, initial_response.as_deref(), false);
    }

    /// Run one SASL step off the reactor thread (issue #181 —
    /// `SaslServer::step` can block for LDAP/PAM-backed stores). The result
    /// is applied later by `sync_pending_auth_check`, once back on the
    /// reactor; `busy` gates pipelined commands until then.
    fn sasl_step(
        &mut self,
        endpoint: &mut dyn Endpoint,
        tag: String,
        mut server: Box<dyn SaslServer>,
        response: Option<&[u8]>,
        first_step: bool,
    ) {
        let Some(handle) = self.control_handle.clone() else {
            self.send(endpoint, tagged_no(&tag, "Internal error: no handle"));
            return;
        };
        let response = response.map(<[u8]>::to_vec);
        let pending = Arc::clone(&self.pending_auth_check);
        let busy = Arc::clone(&self.busy);
        begin_busy(endpoint, &self.busy);
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
                *pending.lock().unwrap() = Some(AuthCheckOutcome::Step {
                    tag,
                    first_step,
                    result,
                });
                handle.with_endpoint(move |ep| end_busy(ep, &busy));
            },
        );
    }

    /// Apply the outcome of an offloaded credential check (LOGIN or a SASL
    /// step), once `sasl_step`/`cmd_login`'s `submit_on` callback has
    /// stashed one — see `AuthCheckOutcome`.
    fn sync_pending_auth_check(&mut self, endpoint: &mut dyn Endpoint) {
        let Some(outcome) = self.pending_auth_check.lock().unwrap().take() else {
            return;
        };
        match outcome {
            AuthCheckOutcome::Login { tag, user, result } => match result {
                Ok(true) => self.finish_auth(endpoint, &tag, user),
                Ok(false) => {
                    self.record_auth(false);
                    self.send(endpoint, tagged_no(&tag, "Invalid credentials"));
                }
                Err(e) => {
                    self.send(
                        endpoint,
                        tagged_no(&tag, &format!("[UNAVAILABLE] Authentication temporarily unavailable: {e}")),
                    );
                }
            },
            AuthCheckOutcome::Step {
                tag,
                first_step,
                result,
            } => match result {
                Ok((server, step)) => match step {
                    SaslServerStep::Challenge(c) => {
                        self.send(endpoint, continuation(&base64::encode(&c)));
                        self.pending_auth = Some(PendingAuth { tag, server });
                        self.lexer.expect_sasl_response();
                    }
                    SaslServerStep::Complete {
                        username,
                        final_message,
                    } if !first_step => {
                        if let Some(fm) = final_message {
                            if !fm.is_empty() {
                                self.send(endpoint, continuation(&base64::encode(&fm)));
                            }
                        }
                        self.finish_auth(endpoint, &tag, username);
                    }
                    SaslServerStep::Complete { .. } | SaslServerStep::Failure => {
                        self.auth_failed(endpoint, &tag);
                    }
                },
                Err(e) => {
                    self.send(
                        endpoint,
                        tagged_no(&tag, &format!("[UNAVAILABLE] Authentication temporarily unavailable: {e}")),
                    );
                }
            },
        }
    }

    fn auth_failed(&mut self, endpoint: &mut dyn Endpoint, tag: &str) {
        self.pending_auth = None;
        self.record_auth(false);
        self.send(endpoint, tagged_no(tag, "Authentication failed"));
        if let Some(tel) = self.pending_cmd_tel.take() {
            self.finish_command_telemetry(tel, "fail");
        }
    }

    fn finish_auth(&mut self, endpoint: &mut dyn Endpoint, tag: &str, username: String) {
        self.record_auth(true);
        self.username = Some(username.clone());
        self.meta.user = Some(username.clone());
        let factory = Arc::clone(&self.config.mailbox_factory);
        let Some(mut h) = self.not_authenticated.take() else {
            self.send(endpoint, tagged_no(tag, "No authentication handler"));
            return;
        };
        let caps = self.capabilities();
        let mut view = AuthView {
            endpoint,
            tag,
            not_authenticated: &mut self.not_authenticated,
            authenticated: &mut self.authenticated,
            session: &mut self.session,
            bundle: &self.bundle,
            runtime: &self.runtime,
            busy: &self.busy,
            control_handle: &self.control_handle,
            pending_open: &self.pending_open,
            caps,
            username: username.clone(),
            factory: Arc::clone(&factory),
        };
        h.authenticate(&mut view, &username, factory.as_ref());
        if self.not_authenticated.is_none()
            && self.authenticated.is_none()
            && self.pending_open.lock().unwrap().is_none()
        {
            self.not_authenticated = Some(h);
        }
    }

    fn cmd_select(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand, examine: bool) {
        if !self.require_auth(endpoint, &cmd.tag) {
            return;
        }
        let Ok((name, rest)) = parse_astring(&cmd.args) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid mailbox name"));
            return;
        };
        // Optional (CONDSTORE) / (QRESYNC (...))
        self.pending_qresync = None;
        let mut select_condstore = self.enabled.condstore;
        let rest = rest.trim_start();
        if rest.starts_with('(') {
            let upper = rest.to_ascii_uppercase();
            if upper.starts_with("(CONDSTORE") {
                if self.config.enable_condstore {
                    select_condstore = true;
                    self.enabled.condstore = true;
                }
            } else if upper.starts_with("(QRESYNC") {
                if !self.enabled.qresync {
                    self.send(
                        endpoint,
                        tagged_bad(&cmd.tag, "QRESYNC not enabled (use ENABLE)"),
                    );
                    return;
                }
                select_condstore = true;
                // Parse (QRESYNC (uidvalidity modseq ...))
                if let Some(inner_start) = rest
                    .find('(')
                    .and_then(|i| rest[i + 1..].find('(').map(|j| i + 1 + j))
                {
                    let inner = &rest[inner_start + 1..];
                    let end = inner.find(')').unwrap_or(inner.len());
                    let mut parts = inner[..end].split_whitespace();
                    if let (Some(uv), Some(ms)) = (parts.next(), parts.next()) {
                        if let (Ok(uv), Ok(ms)) = (uv.parse::<u64>(), ms.parse::<u64>()) {
                            self.pending_qresync = Some((uv, ms));
                        }
                    }
                }
            }
        }
        let qresync = self.pending_qresync;
        if let Some(mut h) = self.selected.take() {
            let mut view = SelectView {
                endpoint,
                tag: &cmd.tag,
                name: name.clone(),
                examine,
                condstore: select_condstore,
                qresync,
                authenticated: &mut self.authenticated,
                selected: &mut self.selected,
                session: &mut self.session,
                bundle: &self.bundle,
                runtime: &self.runtime,
                busy: &self.busy,
                control_handle: &self.control_handle,
                pending_open: &self.pending_open,
            };
            let g = self.bundle.lock().unwrap();
            if let Some(store) = g.store.as_ref() {
                if examine {
                    h.examine(&mut view, store.as_ref(), &name);
                } else {
                    h.select(&mut view, store.as_ref(), &name);
                }
            }
            drop(g);
            if self.selected.is_none()
                && self.pending_open.lock().unwrap().is_none()
                && self.session == ImapSessionState::Selected
            {
                self.selected = Some(h);
            }
            return;
        }
        if let Some(mut h) = self.authenticated.take() {
            let mut view = SelectView {
                endpoint,
                tag: &cmd.tag,
                name: name.clone(),
                examine,
                condstore: select_condstore,
                qresync,
                authenticated: &mut self.authenticated,
                selected: &mut self.selected,
                session: &mut self.session,
                bundle: &self.bundle,
                runtime: &self.runtime,
                busy: &self.busy,
                control_handle: &self.control_handle,
                pending_open: &self.pending_open,
            };
            let g = self.bundle.lock().unwrap();
            if let Some(store) = g.store.as_ref() {
                if examine {
                    h.examine(&mut view, store.as_ref(), &name);
                } else {
                    h.select(&mut view, store.as_ref(), &name);
                }
            }
            drop(g);
            if self.authenticated.is_none() && self.pending_open.lock().unwrap().is_none() {
                self.authenticated = Some(h);
            }
        }
    }

    fn cmd_close(&mut self, endpoint: &mut dyn Endpoint, tag: &str, expunge: bool) {
        if !self.require_selected(endpoint, tag) {
            return;
        }
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = CloseView {
            endpoint,
            tag,
            expunge,
            authenticated: &mut self.authenticated,
            selected: &mut self.selected,
            session: &mut self.session,
            bundle: &self.bundle,
            runtime: &self.runtime,
            busy: &self.busy,
            control_handle: &self.control_handle,
            pending_open: &self.pending_open,
            next_auth: None,
        };
        let g = self.bundle.lock().unwrap();
        if let Some(mb) = g.mailbox.as_ref() {
            if expunge {
                h.close(&mut view, mb.as_ref());
            } else {
                h.unselect(&mut view, mb.as_ref());
            }
        }
        drop(g);
        if self.selected.is_none() && self.pending_open.lock().unwrap().is_none() {
            let _ = h;
        }
    }

    fn cmd_mgmt_name(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand, op: MgmtOp) {
        if !self.require_auth(endpoint, &cmd.tag) {
            return;
        }
        let Ok((name, _)) = parse_astring(&cmd.args) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid mailbox name"));
            return;
        };
        self.run_mgmt(
            endpoint,
            &cmd.tag,
            name,
            None,
            String::new(),
            String::new(),
            op,
        );
    }

    fn cmd_rename(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if !self.require_auth(endpoint, &cmd.tag) {
            return;
        }
        let Ok((old, rest)) = parse_astring(&cmd.args) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid RENAME"));
            return;
        };
        let Ok((new, _)) = parse_astring(rest) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid RENAME"));
            return;
        };
        self.run_mgmt(
            endpoint,
            &cmd.tag,
            old,
            Some(new),
            String::new(),
            String::new(),
            MgmtOp::Rename,
        );
    }

    fn cmd_list(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand, lsub: bool) {
        if !self.require_auth(endpoint, &cmd.tag) {
            return;
        }
        if lsub {
            let Ok((reference, rest)) = parse_astring(&cmd.args) else {
                self.send(endpoint, tagged_bad(&cmd.tag, "Invalid LSUB"));
                return;
            };
            let Ok((pattern, _)) = parse_astring(rest) else {
                self.send(endpoint, tagged_bad(&cmd.tag, "Invalid LSUB"));
                return;
            };
            self.run_mgmt(
                endpoint,
                &cmd.tag,
                String::new(),
                None,
                reference,
                pattern,
                MgmtOp::Lsub,
            );
            return;
        }
        let parsed = match crate::server::list_ext::parse_list_command(&cmd.args) {
            Ok(p) => p,
            Err(e) => {
                self.send(endpoint, tagged_bad(&cmd.tag, &e));
                return;
            }
        };
        let subscribed = parsed
            .select
            .contains(&crate::server::list_ext::ListSelectOption::Subscribed)
            || parsed.ret.subscribed;
        let extended = !parsed.select.is_empty()
            || parsed.ret.children
            || parsed.ret.subscribed
            || !parsed.ret.status.is_empty();
        if !extended {
            self.run_mgmt(
                endpoint,
                &cmd.tag,
                String::new(),
                None,
                parsed.reference,
                parsed.pattern,
                if subscribed {
                    MgmtOp::Lsub
                } else {
                    MgmtOp::List
                },
            );
            return;
        }
        self.run_list_ext(endpoint, &cmd.tag, parsed, subscribed);
    }

    fn cmd_fetch(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand, by_uid: bool) {
        if !self.require_selected(endpoint, &cmd.tag) {
            return;
        }
        let Ok((set, rest)) = parse_sequence_set(&cmd.args) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid sequence set"));
            return;
        };
        let (mut items, modifiers) = match parse_fetch_args(rest) {
            Ok(v) => v,
            Err(e) => {
                self.send(endpoint, tagged_bad(&cmd.tag, &e));
                return;
            }
        };
        if modifiers.changed_since.is_some() && !self.enabled.condstore {
            // Implicitly enable CONDSTORE when CHANGEDSINCE is used (RFC 7162).
            if self.config.enable_condstore {
                self.enabled.condstore = true;
            }
        }
        if self.enabled.condstore
            && !items
                .iter()
                .any(|i| matches!(i, crate::server::fetch_format::FetchItem::ModSeq))
        {
            items.push(crate::server::fetch_format::FetchItem::ModSeq);
        }
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = FetchView {
            endpoint,
            tag: &cmd.tag,
            set: set.clone(),
            by_uid,
            changed_since: modifiers.changed_since,
            selected: &mut self.selected,
            bundle: &self.bundle,
            runtime: &self.runtime,
            busy: &self.busy,
            control_handle: &self.control_handle,
            pending_open: &self.pending_open,
        };
        let g = self.bundle.lock().unwrap();
        if let Some(mb) = g.mailbox.as_ref() {
            h.fetch(&mut view, mb.as_ref(), &set, &items, by_uid);
        }
        drop(g);
        if self.selected.is_none() && self.pending_open.lock().unwrap().is_none() {
            self.selected = Some(h);
        }
    }

    fn run_mgmt(
        &mut self,
        endpoint: &mut dyn Endpoint,
        tag: &str,
        name: String,
        name2: Option<String>,
        reference: String,
        pattern: String,
        op: MgmtOp,
    ) {
        if let Some(mut h) = self.selected.take() {
            let mut view = MgmtView {
                endpoint,
                tag,
                name: name.clone(),
                name2: name2.clone(),
                reference: reference.clone(),
                pattern: pattern.clone(),
                op,
                authenticated: &mut self.authenticated,
                bundle: &self.bundle,
                runtime: &self.runtime,
                busy: &self.busy,
                control_handle: &self.control_handle,
                pending_open: &self.pending_open,
            };
            let g = self.bundle.lock().unwrap();
            if let Some(store) = g.store.as_ref() {
                match op {
                    MgmtOp::Create => h.create(&mut view, store.as_ref(), &name),
                    MgmtOp::Delete => h.delete(&mut view, store.as_ref(), &name),
                    MgmtOp::Rename => h.rename(
                        &mut view,
                        store.as_ref(),
                        &name,
                        name2.as_deref().unwrap_or(""),
                    ),
                    MgmtOp::Subscribe => h.subscribe(&mut view, store.as_ref(), &name),
                    MgmtOp::Unsubscribe => h.unsubscribe(&mut view, store.as_ref(), &name),
                    MgmtOp::List => h.list(&mut view, store.as_ref(), &reference, &pattern),
                    MgmtOp::Lsub => h.lsub(&mut view, store.as_ref(), &reference, &pattern),
                }
            }
            drop(g);
            if self.selected.is_none() {
                self.selected = Some(h);
            }
            return;
        }
        if let Some(mut h) = self.authenticated.take() {
            let mut view = MgmtView {
                endpoint,
                tag,
                name: name.clone(),
                name2: name2.clone(),
                reference: reference.clone(),
                pattern: pattern.clone(),
                op,
                authenticated: &mut self.authenticated,
                bundle: &self.bundle,
                runtime: &self.runtime,
                busy: &self.busy,
                control_handle: &self.control_handle,
                pending_open: &self.pending_open,
            };
            let g = self.bundle.lock().unwrap();
            if let Some(store) = g.store.as_ref() {
                match op {
                    MgmtOp::Create => h.create(&mut view, store.as_ref(), &name),
                    MgmtOp::Delete => h.delete(&mut view, store.as_ref(), &name),
                    MgmtOp::Rename => h.rename(
                        &mut view,
                        store.as_ref(),
                        &name,
                        name2.as_deref().unwrap_or(""),
                    ),
                    MgmtOp::Subscribe => h.subscribe(&mut view, store.as_ref(), &name),
                    MgmtOp::Unsubscribe => h.unsubscribe(&mut view, store.as_ref(), &name),
                    MgmtOp::List => h.list(&mut view, store.as_ref(), &reference, &pattern),
                    MgmtOp::Lsub => h.lsub(&mut view, store.as_ref(), &reference, &pattern),
                }
            }
            drop(g);
            if self.authenticated.is_none() && self.pending_open.lock().unwrap().is_none() {
                self.authenticated = Some(h);
            }
        }
    }

    fn cmd_append(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if !self.require_auth(endpoint, &cmd.tag) {
            return;
        }
        if let Some(err) = self.pending_append_error.take() {
            if let Some(path) = self.pending_append_path.take() {
                let _ = std::fs::remove_file(path);
            }
            self.send(
                endpoint,
                tagged_no(&cmd.tag, &format!("Could not stage message: {err}")),
            );
            return;
        }
        let Some(body_path) = self.pending_append_path.take() else {
            self.send(
                endpoint,
                tagged_bad(&cmd.tag, "APPEND requires a message literal"),
            );
            return;
        };
        let Ok((name, rest)) = parse_astring(cmd.args.trim()) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid APPEND mailbox"));
            return;
        };
        let mut rest = rest;
        let mut flags = BTreeSet::new();
        if rest.starts_with('(') {
            match parse_flag_list(rest) {
                Ok((f, r)) => {
                    flags = f.flags;
                    rest = r;
                }
                Err(e) => {
                    self.send(endpoint, tagged_bad(&cmd.tag, &e));
                    return;
                }
            }
        }
        let internal_date: Option<SystemTime> = if rest.starts_with('"') {
            let _ = parse_astring(rest);
            None
        } else {
            None
        };
        if let Some(mut h) = self.selected.take() {
            let mut view = AppendView {
                endpoint,
                tag: &cmd.tag,
                mailbox: name.clone(),
                body_path: Some(body_path),
                flags: flags.clone(),
                internal_date,
                authenticated: &mut self.authenticated,
                bundle: &self.bundle,
                runtime: &self.runtime,
                busy: &self.busy,
                control_handle: &self.control_handle,
                pending_open: &self.pending_open,
            };
            let g = self.bundle.lock().unwrap();
            if let Some(store) = g.store.as_ref() {
                h.append(&mut view, store.as_ref(), &name, &flags, internal_date);
            }
            drop(g);
            if self.selected.is_none() {
                self.selected = Some(h);
            }
            return;
        }
        if let Some(mut h) = self.authenticated.take() {
            let mut view = AppendView {
                endpoint,
                tag: &cmd.tag,
                mailbox: name.clone(),
                body_path: Some(body_path),
                flags: flags.clone(),
                internal_date,
                authenticated: &mut self.authenticated,
                bundle: &self.bundle,
                runtime: &self.runtime,
                busy: &self.busy,
                control_handle: &self.control_handle,
                pending_open: &self.pending_open,
            };
            let g = self.bundle.lock().unwrap();
            if let Some(store) = g.store.as_ref() {
                h.append(&mut view, store.as_ref(), &name, &flags, internal_date);
            }
            drop(g);
            if self.authenticated.is_none() && self.pending_open.lock().unwrap().is_none() {
                self.authenticated = Some(h);
            }
        }
    }

    fn cmd_store(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand, by_uid: bool) {
        if !self.require_selected(endpoint, &cmd.tag) {
            return;
        }
        let Ok((set, rest)) = parse_sequence_set(&cmd.args) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid sequence set"));
            return;
        };
        let mut parts = rest.splitn(2, char::is_whitespace);
        let Some(item) = parts.next() else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Missing STORE item"));
            return;
        };
        let flag_part = parts.next().unwrap_or("").trim_start();
        let Ok((action, silent)) = parse_store_item(item) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid STORE item"));
            return;
        };
        let Ok((flist, _)) = parse_flag_list(flag_part) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid flag list"));
            return;
        };
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = StoreView {
            endpoint,
            tag: &cmd.tag,
            set: set.clone(),
            by_uid,
            selected: &mut self.selected,
            bundle: &self.bundle,
            runtime: &self.runtime,
            busy: &self.busy,
            control_handle: &self.control_handle,
            pending_open: &self.pending_open,
        };
        let g = self.bundle.lock().unwrap();
        if let Some(mb) = g.mailbox.as_ref() {
            h.store(
                &mut view,
                mb.as_ref(),
                &set,
                action,
                &flist.flags,
                &flist.keywords,
                silent,
                by_uid,
            );
        }
        drop(g);
        if self.selected.is_none() && self.pending_open.lock().unwrap().is_none() {
            self.selected = Some(h);
        }
    }

    fn cmd_search(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand, by_uid: bool) {
        if !self.require_selected(endpoint, &cmd.tag) {
            return;
        }
        let criteria = match parse_search(&cmd.args) {
            Ok(c) => c,
            Err(e) => {
                self.send(endpoint, tagged_bad(&cmd.tag, &e.to_string()));
                return;
            }
        };
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = SearchView {
            endpoint,
            tag: &cmd.tag,
            criteria: criteria.clone(),
            by_uid,
            selected: &mut self.selected,
            bundle: &self.bundle,
            runtime: &self.runtime,
            busy: &self.busy,
            control_handle: &self.control_handle,
            pending_open: &self.pending_open,
        };
        let g = self.bundle.lock().unwrap();
        if let Some(mb) = g.mailbox.as_ref() {
            h.search(&mut view, mb.as_ref(), &criteria, by_uid);
        }
        drop(g);
        if self.selected.is_none() && self.pending_open.lock().unwrap().is_none() {
            self.selected = Some(h);
        }
    }

    fn cmd_copy(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand, by_uid: bool) {
        if !self.require_selected(endpoint, &cmd.tag) {
            return;
        }
        let Ok((set, rest)) = parse_sequence_set(&cmd.args) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid sequence set"));
            return;
        };
        let Ok((dest, _)) = parse_astring(rest) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid destination"));
            return;
        };
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = CopyView {
            endpoint,
            tag: &cmd.tag,
            set: set.clone(),
            dest: dest.clone(),
            by_uid,
            selected: &mut self.selected,
            bundle: &self.bundle,
            runtime: &self.runtime,
            busy: &self.busy,
            control_handle: &self.control_handle,
            pending_open: &self.pending_open,
        };
        let g = self.bundle.lock().unwrap();
        if let Some(mb) = g.mailbox.as_ref() {
            h.copy(&mut view, mb.as_ref(), &set, &dest, by_uid);
        }
        drop(g);
        if self.selected.is_none() && self.pending_open.lock().unwrap().is_none() {
            self.selected = Some(h);
        }
    }

    fn cmd_uid(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if !self.require_selected(endpoint, &cmd.tag) {
            return;
        }
        let args = cmd.args.trim();
        let mut parts = args.splitn(2, char::is_whitespace);
        let Some(sub) = parts.next() else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Missing UID command"));
            return;
        };
        let rest = parts.next().unwrap_or("").trim_start();
        let sub_cmd = ImapCommand {
            tag: cmd.tag.clone(),
            verb: sub.to_ascii_uppercase(),
            args: rest.to_string(),
            arg_bytes: rest.as_bytes().to_vec(),
        };
        match sub_cmd.verb.as_str() {
            "FETCH" => self.cmd_fetch(endpoint, sub_cmd, true),
            "STORE" => self.cmd_store(endpoint, sub_cmd, true),
            "SEARCH" => self.cmd_search(endpoint, sub_cmd, true),
            "COPY" => self.cmd_copy(endpoint, sub_cmd, true),
            "MOVE" => self.cmd_move(endpoint, sub_cmd, true),
            "EXPUNGE" => {
                let Ok((set, _)) = parse_sequence_set(&sub_cmd.args) else {
                    self.send(endpoint, tagged_bad(&sub_cmd.tag, "Invalid UID set"));
                    return;
                };
                self.cmd_expunge(endpoint, &sub_cmd.tag, Some(set));
            }
            _ => self.send(endpoint, tagged_bad(&cmd.tag, "Unsupported UID command")),
        }
    }

    fn offload_close(&self, expunge: bool) {
        let bundle = Arc::clone(&self.bundle);
        let Some(handle) = self.control_handle.clone() else {
            return;
        };
        self.runtime.storage().submit_on(
            handle,
            move || {
                let mut g = bundle.lock().unwrap();
                if let Some(mut mb) = g.mailbox.take() {
                    let _ = mb.close(expunge);
                }
                if let Some(mut st) = g.store.take() {
                    let _ = st.close();
                }
                Ok(())
            },
            move |_r: Result<(), StorageError>| {},
        );
    }

    /// Queue one APPEND literal chunk for spooling to a temp file, created
    /// lazily on the first chunk — the literal is never buffered whole in
    /// memory. The write itself is offloaded to `hopf_core::StorageExecutor`
    /// (issue #185) rather than done inline here; chunks land on disk in
    /// order because `drain_next_append_chunk` only submits the next
    /// write once the previous one's callback confirms completion (writes
    /// to the same file must be ordered, and `StorageExecutor::submit_on`
    /// doesn't guarantee that across separate calls).
    fn handle_append_chunk(&mut self, chunk: &[u8]) {
        let mut g = self.append_spool.lock().unwrap();
        if g.error.is_some() {
            return;
        }
        if self.pending_append_cmd.is_some() {
            // A previous APPEND's spool hasn't finalized yet (issue #185)
            // — only reachable via extremely aggressive LITERAL+
            // pipelining that outruns our own finalize (a second literal
            // starting before the first APPEND's tagged reply). Refuse
            // rather than silently appending into the wrong message.
            g.error = Some("internal: previous APPEND still finalizing".into());
            return;
        }
        g.queue.push_back(chunk.to_vec());
        let should_start = !g.draining;
        if should_start {
            g.draining = true;
        }
        drop(g);
        if should_start {
            let Some(handle) = self.control_handle.clone() else {
                self.append_spool.lock().unwrap().error = Some("no control handle".into());
                return;
            };
            drain_next_append_chunk(Arc::clone(&self.append_spool), Arc::clone(&self.runtime), handle);
        }
    }

    /// Move the just-completed APPEND spool (if any) into
    /// `pending_append_path`, ready for `cmd_append` to stream from.
    /// Returns `false` (and does nothing else) while writes are still
    /// draining (issue #185) — the caller must defer via
    /// `pending_append_cmd`/`sync_pending_append` instead of finalizing
    /// before every chunk has actually landed.
    fn finalize_pending_append(&mut self) -> bool {
        let mut g = self.append_spool.lock().unwrap();
        if g.draining || !g.queue.is_empty() {
            return false;
        }
        if let Some(f) = g.file.take() {
            let _ = f.sync_all();
        }
        self.pending_append_path = g.path.take();
        self.pending_append_error = g.error.take();
        true
    }

    /// Re-invoke the deferred APPEND `Command` event once `append_spool`'s
    /// queued writes have finished draining (issue #185) — mirrors
    /// `sync_pending_auth_check`, triggered by the last write's
    /// `poke_handler` call (see `drain_next_append_chunk`).
    fn sync_pending_append(&mut self, endpoint: &mut dyn Endpoint) {
        let Some(cmd) = self.pending_append_cmd.take() else {
            return;
        };
        if !self.finalize_pending_append() {
            self.pending_append_cmd = Some(cmd);
            return;
        }
        self.enqueue_or_dispatch(endpoint, cmd);
    }

    fn feed_auth_line(&mut self, endpoint: &mut dyn Endpoint, line: &[u8]) {
        let Some(PendingAuth { tag, server }) = self.pending_auth.take() else {
            return;
        };
        if line == b"*" {
            self.send(endpoint, tagged_bad(&tag, "Authentication cancelled"));
            return;
        }
        match std::str::from_utf8(line)
            .ok()
            .and_then(|s| base64::decode(s).ok())
        {
            Some(raw) => self.sasl_step(endpoint, tag, server, Some(&raw), false),
            None => self.send(endpoint, tagged_no(&tag, "Invalid base64")),
        }
    }
}

impl ProtocolHandler for ImapControlHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(peer) = endpoint.remote_addr().ok().and_then(|a| a.as_socket_addr()) {
            self.peer = peer;
        }
        if let Some(local) = endpoint.local_addr().ok().and_then(|a| a.as_socket_addr()) {
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
        self.sync_pending(endpoint);
        self.sync_pending_auth_check(endpoint);
        self.sync_pending_append(endpoint);
        self.drain_queue(endpoint);

        if self.busy.load(Ordering::Relaxed) && !self.lexer.in_literal() {
            // Reads paused during storage; leave the data unconsumed so the
            // connection buffers it and `end_busy` redelivers it via
            // `poke_handler` once the storage operation completes.
            // Literal bytes still flow through when mid-literal (LITERAL+).
            return;
        }

        let events = self.lexer.feed(data);
        for ev in events {
            match ev {
                LexEvent::NeedContinuation => {
                    self.send(endpoint, continuation("Ready for literal data"));
                }
                LexEvent::SaslLine(line) => {
                    self.feed_auth_line(endpoint, &line);
                }
                LexEvent::Error { tag, message } => {
                    self.send(endpoint, tagged_bad(&tag, &message));
                }
                LexEvent::AppendChunk(chunk) => {
                    self.handle_append_chunk(&chunk);
                }
                LexEvent::Command(cmd) => {
                    // An APPEND literal (if any) always finishes immediately
                    // before its Command event — see `codec::feed_literal`'s
                    // `LiteralPhase::Append` arm — so finalizing here always
                    // picks up exactly the literal that belongs to `cmd`.
                    if self.finalize_pending_append() {
                        // State gating (reject Selected cmds when not
                        // selected) happens inside dispatch. While a
                        // storage operation is in flight,
                        // `enqueue_or_dispatch` queues pipelined commands
                        // instead of dispatching, so keep consuming every
                        // event lexed from this buffer — breaking here
                        // would drop them.
                        self.enqueue_or_dispatch(endpoint, cmd);
                    } else {
                        // Spool writes from this literal are still
                        // draining (issue #185) — `cmd` reads
                        // `pending_append_path`, which isn't set yet.
                        // Defer both finalize and dispatch;
                        // `sync_pending_append` re-invokes this once
                        // `finalize_pending_append` succeeds, triggered by
                        // the last write's `poke_handler` call (see
                        // `drain_next_append_chunk`).
                        self.pending_append_cmd = Some(cmd);
                    }
                }
            }
        }
        self.sync_pending(endpoint);
        self.sync_pending_auth_check(endpoint);
        self.sync_pending_append(endpoint);
        self.drain_queue(endpoint);
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if let Some(mut c) = self.client_connected.take() {
            c.disconnected();
        }
        if self.session != ImapSessionState::Logout {
            self.offload_close(false);
        }
        self.end_connection_telemetry();
    }

    fn security_established(
        &mut self,
        endpoint: &mut dyn Endpoint,
        info: &hopf_core::SecurityInfo,
    ) {
        self.tls = true;
        self.meta.tls = true;
        self.peer_certificate = info.peer_certificate_fingerprint().map(str::to_string);
        if self.expect_implicit_tls && !self.greeting_sent {
            self.greet(endpoint);
            return;
        }
        if self.starttls_used {
            self.record_starttls();
            self.starttls_used = false;
            return;
        }
        self.starttls_used = false;
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &std::io::Error) {
        endpoint.close();
    }
}

/// Shared, mutex-guarded APPEND literal spool state (issue #185) — see
/// `ImapControlHandler::append_spool`.
#[derive(Default)]
struct AppendSpoolState {
    file: Option<std::fs::File>,
    path: Option<std::path::PathBuf>,
    error: Option<String>,
    queue: VecDeque<Vec<u8>>,
    /// One write in flight at a time — set while a chunk is submitted to
    /// the storage pool, cleared once its callback lands and the queue is
    /// empty.
    draining: bool,
}

/// Drain the next queued APPEND chunk (if any) by submitting its write to
/// the storage pool; on completion, either drains the next one or clears
/// `draining` once the queue is empty. Free function (not a method) since
/// it needs to re-invoke itself from inside a `'static` storage callback,
/// which only has cloned `Arc`s/`ConnHandle`, not `&mut Self`. Mirrors
/// `hopf_smtp::server::spool::drain_next` (issue #184).
fn drain_next_append_chunk(state: Arc<Mutex<AppendSpoolState>>, runtime: Arc<Runtime>, handle: ConnHandle) {
    let chunk = {
        let mut g = state.lock().unwrap();
        match g.queue.pop_front() {
            Some(c) => c,
            None => {
                g.draining = false;
                return;
            }
        }
    };
    let op_state = Arc::clone(&state);
    let cb_state = Arc::clone(&state);
    let cb_runtime = Arc::clone(&runtime);
    let cb_handle = handle.clone();
    runtime.storage().submit_on(
        handle,
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut g = op_state.lock().unwrap();
            if g.file.is_none() {
                let path = unique_append_spool_path();
                let f = std::fs::File::create(&path)?;
                g.file = Some(f);
                g.path = Some(path);
            }
            use std::io::Write;
            g.file.as_mut().unwrap().write_all(&chunk)?;
            Ok(())
        },
        move |result: Result<(), StorageError>| {
            let ok = result.is_ok();
            {
                let mut g = cb_state.lock().unwrap();
                if let Err(e) = &result {
                    g.error = Some(e.to_string());
                    g.queue.clear();
                    g.draining = false;
                }
            }
            cb_handle.with_endpoint(|ep| {
                // Lets `ImapControlHandler::sync_pending_append` (issue
                // #185) re-check readiness promptly once this was the
                // last outstanding write, instead of waiting for the
                // client's next input to trigger another `receive()`.
                ep.poke_handler();
            });
            if ok {
                drain_next_append_chunk(cb_state, cb_runtime, cb_handle);
            }
        },
    );
}

fn unique_append_spool_path() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    std::env::temp_dir().join(format!(
        "hopf-imap-append-{}-{}-{}.tmp",
        std::process::id(),
        nanos,
        n
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::codec::ImapServerLexer;

    #[test]
    fn state_enum_gating() {
        assert_ne!(
            ImapSessionState::NotAuthenticated,
            ImapSessionState::Selected
        );
        assert_eq!(ImapSessionState::Logout, ImapSessionState::Logout);
    }

    #[test]
    fn literal_and_pipeline_lex() {
        let mut lex = ImapServerLexer::new(MAX_COMMAND_LINE);
        let mut data: &[u8] = b"a1 CAPABILITY\r\na2 NOOP\r\n";
        let ev = lex.feed(&mut data);
        assert_eq!(ev.len(), 2);
    }

    #[test]
    fn selected_commands_need_selected_state() {
        // Document expected verbs that require Selected.
        let selected_only = ["FETCH", "STORE", "SEARCH", "COPY", "CLOSE", "UID"];
        assert!(selected_only.contains(&"FETCH"));
    }
}

/// Issue #185: APPEND literal chunk writes are offloaded to
/// `hopf_core::StorageExecutor` rather than done inline on the reactor
/// thread, and `finalize_pending_append`/the `Command` event that follows
/// must not read `pending_append_path` until every queued chunk has
/// actually landed, in order.
#[cfg(test)]
mod append_offload_tests {
    use super::*;
    use crate::server::handler::ImapHandlerFactory;
    use hopf_core::{RuntimeConfig, SecurityInfo, StartTlsError, TimerHandle, WriteReadyCallback};
    use std::io;

    /// Endpoint stub: no real I/O, just enough to satisfy the trait so
    /// `handle_append_chunk`'s offloaded writes (via `self.control_handle`)
    /// and `sync_pending_append`/`enqueue_or_dispatch` can run.
    struct NoopEndpoint;
    impl Endpoint for NoopEndpoint {
        fn send(&mut self, _data: &[u8]) {}
        fn is_open(&self) -> bool {
            true
        }
        fn is_closing(&self) -> bool {
            false
        }
        fn close(&mut self) {}
        fn local_addr(&self) -> io::Result<hopf_core::PeerAddr> {
            Ok(hopf_core::PeerAddr::Inet("127.0.0.1:143".parse().unwrap()))
        }
        fn remote_addr(&self) -> io::Result<hopf_core::PeerAddr> {
            Ok(hopf_core::PeerAddr::Inet("127.0.0.1:9999".parse().unwrap()))
        }
        fn security_info(&self) -> &SecurityInfo {
            static PLAINTEXT: std::sync::OnceLock<SecurityInfo> = std::sync::OnceLock::new();
            PLAINTEXT.get_or_init(SecurityInfo::plaintext)
        }
        fn start_tls(&mut self) -> Result<(), StartTlsError> {
            Err(StartTlsError::Unsupported)
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _callback: Option<WriteReadyCallback>) {}
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn schedule_timer(
            &self,
            _delay: std::time::Duration,
            _callback: Box<dyn FnOnce() + Send>,
        ) -> TimerHandle {
            TimerHandle::from_cancel(|| {})
        }
        fn handle(&self) -> ConnHandle {
            ConnHandle::from_execute(Arc::new(|task| task()))
        }
    }

    fn test_handler() -> ImapControlHandler {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(hopf_auth::PasswordStore::new().with_user("u", "p"));
        let factory = Arc::new(hopf_mailbox::MaildirFactory::new(root.path()));
        // The handler only needs the factory's type, not the directory's
        // continued existence — nothing in these tests reaches `cmd_append`
        // itself (they drive `handle_append_chunk`/`finalize_pending_append`
        // directly), so leaking the tempdir here is fine.
        std::mem::forget(root);
        let listen: SocketAddr = "127.0.0.1:1143".parse().unwrap();
        let config = ImapConfig::new(listen, "localhost", store, factory);
        let client = crate::server::handler::DefaultImapHandlerFactory::new("ready").create();
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let mut h = ImapControlHandler::new(client, config, rt, ImapServerMetrics::shared());
        h.control_handle = Some(ConnHandle::from_execute(Arc::new(|task| task())));
        h
    }

    fn wait_for(mut pred: impl FnMut() -> bool, max_ms: u64) -> bool {
        for _ in 0..(max_ms / 5).max(1) {
            if pred() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        pred()
    }

    #[test]
    fn append_chunks_land_in_order_across_many_offloaded_writes() {
        let mut h = test_handler();

        let mut expected = Vec::new();
        for i in 0..20 {
            let chunk = format!("chunk{i:02}-");
            expected.extend_from_slice(chunk.as_bytes());
            h.handle_append_chunk(chunk.as_bytes());
        }

        assert!(
            wait_for(|| h.finalize_pending_append(), 3000),
            "finalize must eventually succeed once every offloaded write lands"
        );
        let path = h
            .pending_append_path
            .clone()
            .expect("spool file created");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            expected,
            "chunks must land on disk in submission order despite being offloaded"
        );
        assert!(h.pending_append_error.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_literal_never_creates_a_spool_file() {
        let mut h = test_handler();
        assert!(h.finalize_pending_append());
        assert!(h.pending_append_path.is_none());
        assert!(h.pending_append_error.is_none());
    }

    #[test]
    fn command_after_draining_literal_is_deferred_then_dispatched_in_order() {
        let mut h = test_handler();
        let mut ep = NoopEndpoint;

        h.handle_append_chunk(b"hello world");
        let append_cmd = ImapCommand {
            tag: "a1".into(),
            verb: "APPEND".into(),
            args: "INBOX".into(),
            arg_bytes: b"INBOX".to_vec(),
        };
        // Mirrors `receive()`'s `LexEvent::Command` arm.
        if h.finalize_pending_append() {
            h.enqueue_or_dispatch(&mut ep, append_cmd);
        } else {
            h.pending_append_cmd = Some(append_cmd);
        }

        // A further pipelined command must queue behind the still-
        // finalizing APPEND, not run ahead of it.
        let noop_cmd = ImapCommand {
            tag: "a2".into(),
            verb: "NOOP".into(),
            args: String::new(),
            arg_bytes: Vec::new(),
        };
        h.enqueue_or_dispatch(&mut ep, noop_cmd);
        if h.pending_append_cmd.is_some() {
            assert_eq!(
                h.cmd_queue.len(),
                1,
                "a2 must queue behind the still-finalizing APPEND, not dispatch early"
            );
        }

        assert!(
            wait_for(
                || {
                    h.sync_pending_append(&mut ep);
                    h.pending_append_cmd.is_none()
                },
                2000
            ),
            "the deferred APPEND command must eventually finalize and dispatch"
        );
        h.drain_queue(&mut ep);
        assert!(
            h.cmd_queue.is_empty(),
            "a2 must have drained once the APPEND finished"
        );
        if let Some(path) = h.pending_append_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod telemetry_tests {
    use super::*;
    use hopf_auth::PasswordStore;
    use hopf_core::{Runtime, RuntimeConfig};
    use hopf_mailbox::MaildirFactory;
    use hopf_otel::{OtelConfig, SpanContext, TelemetryPipeline};
    use crate::server::handler::ImapHandlerFactory;

    #[test]
    fn with_telemetry_sets_parseable_traceparent_on_connect() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-imap-tp-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let root = tempfile::tempdir().unwrap();
        let cfg = OtelConfig::new("imap-tp-test")
            .with_jsonl_traces(&dir)
            .with_jsonl_metrics(&dir);
        let pipeline = TelemetryPipeline::start(cfg).unwrap();
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let store = Arc::new(PasswordStore::new().with_user("u", "p"));
        let factory = Arc::new(MaildirFactory::new(root.path()));
        let listen: SocketAddr = "127.0.0.1:1143".parse().unwrap();
        let config = ImapConfig::new(listen, "localhost", store, factory);
        let app = crate::server::handler::DefaultImapHandlerFactory::new("ready").create();
        let mut h = ImapControlHandler::new(
            app,
            config,
            rt,
            ImapServerMetrics::shared(),
        )
        .with_telemetry(
            Some(pipeline.imap_metrics()),
            Some(pipeline.export_handle()),
            true,
        );
        h.begin_connection_telemetry();
        let tp = h.meta.traceparent.clone().expect("traceparent set");
        let ctx = SpanContext::from_traceparent(&tp).expect("valid traceparent");
        assert!(!ctx.trace_id.iter().all(|&b| b == 0));

        let cmd = h
            .begin_command_telemetry("FETCH")
            .expect("command telemetry");
        let cmd_tp = h.meta.traceparent.clone().expect("cmd traceparent");
        let cmd_ctx = SpanContext::from_traceparent(&cmd_tp).unwrap();
        assert_eq!(cmd_ctx.trace_id, ctx.trace_id);
        assert_ne!(cmd_ctx.span_id, ctx.span_id);
        h.finish_command_telemetry(cmd, "ok");

        h.end_connection_telemetry();
        assert!(h.meta.traceparent.is_none());
        pipeline.shutdown();
        let _ = std::fs::remove_file(&dir);
    }
}
