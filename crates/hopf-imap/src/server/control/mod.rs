// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP control-connection protocol handler.

mod ext;

use std::collections::VecDeque;
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

use crate::compress::{CompressingEndpoint, ImapCompressLayer};
use crate::enable::EnabledExtensions;
use crate::server::capability::build_capabilities;
use crate::server::grammar::Request;
use crate::server::list_ext::ListCommand;
use crate::server::handler::StoreAction;
use hopf_mailbox::{MessageSet, SearchCriteria};
use crate::server::sort::SortCriterion;
use crate::server::codec::{
    BTreeSetFlags, ImapCommand,
    ImapServerLexer, LexEvent, MAX_COMMAND_LINE,
};
use crate::server::fetch_format::{FetchItem, FetchModifiers};
use crate::server::handler::{
    AuthenticatedHandler, ClientConnected, ImapConnectionMetadata, NotAuthenticatedHandler,
    SelectedHandler, StoreRequest,
};
use crate::server::idle::{is_idle_done, IdleState};
use crate::server::metrics::ImapServerMetrics;
use crate::server::reply::{continuation, tagged_bad, tagged_no, tagged_ok, untagged};
use crate::server::service::ImapConfig;
use crate::server::session::ImapSessionState;
use crate::server::thread::ThreadAlgorithm;
use crate::server::views::{
    begin_busy, end_busy, AppendView, AuthView, CloseView, ConnectedView, CopyView, FetchView,
    MgmtOp, MgmtView, SearchView, SelectView, SortView, StoreView, ThreadView,
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
    Sort {
        tag: String,
        #[allow(dead_code)]
        by_uid: bool,
    },
    /// `payload` is the response text for `* THREAD ...`, or empty when
    /// there is nothing to thread — RFC 5256 sends no untagged THREAD
    /// response at all in that case (unlike SEARCH/SORT, which always
    /// send one, possibly with no numbers).
    Thread {
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
    /// The mechanism has succeeded for this user, and its final data has been
    /// sent as a `+`: the client's empty line is all that is awaited before
    /// the command completes (RFC 4422 §3.5).
    completed: Option<String>,
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
    /// Commands read but not yet run, in order: one waits while a storage
    /// operation is in flight, and an APPEND also while its body is still
    /// being written to the disk.
    cmd_queue: VecDeque<QueuedCommand>,
    pending_auth: Option<PendingAuth>,
    pending_auth_check: Arc<Mutex<Option<AuthCheckOutcome>>>,
    /// APPEND literal being spooled to a temp file as chunks arrive — never
    /// buffered whole in memory (see `AppendChunk`/`seal_append_spool`). When
    /// the APPEND's command has been read, the spool is sealed into its
    /// [`QueuedCommand`] and this is replaced by a fresh one, so literals
    /// pipelined one after another each get a file of their own.
    /// Writes are offloaded to `hopf_core::StorageExecutor` (issue #185)
    /// rather than done inline on the reactor thread; shared (not a plain
    /// field) so the storage-pool write callback, which only ever gets a
    /// cloned `Arc`, can safely reach it.
    append_spool: Arc<Mutex<AppendSpoolState>>,
    /// First spool write error, if any.
    pending_append_error: Option<String>,
    /// The spool path of the APPEND being run, ready for `cmd_append` to
    /// stream from — `None` path with no error means a zero-length (`{0}`)
    /// literal.
    pending_append_path: Option<std::path::PathBuf>,
    pending_open: Arc<Mutex<Option<PendingOpen>>>,
    /// Per-session ENABLE set.
    enabled: EnabledExtensions,
    /// IDLE session.
    idle: IdleState,
    /// RFC 5465 NOTIFY registration (see [`crate::server::notify`]).
    notify: crate::server::notify::NotifyShared,
    /// QRESYNC parameters from the last SELECT (uidvalidity, modseq).
    pending_qresync: Option<(u64, u64)>,
    otel_metrics: Option<Arc<OtelImapMetrics>>,
    export: Option<ExportHandle>,
    traces_enabled: bool,
    conn_trace: Option<Trace>,
    pending_cmd_tel: Option<CommandTelemetry>,
    /// RFC 4978 COMPRESS DEFLATE layer, once negotiated — `None` means the
    /// connection is (still) uncompressed. Temporarily taken out (and put
    /// back) by `receive()` while draining one inbound chunk, so
    /// `cmd_compress`'s "already active" check cannot use this directly —
    /// see `compress_active`.
    compress: Option<ImapCompressLayer>,
    /// Mirrors `compress.is_some()`, except it stays `true` for the whole
    /// `receive()` call that activated compression — including a
    /// re-entrant `COMPRESS` command the lexer produces from the *same*
    /// inbound chunk, while `compress` itself is transiently `None`
    /// (taken out for that call's `CompressingEndpoint`).
    compress_active: bool,
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
            pending_open: Arc::new(Mutex::new(None)),
            enabled: EnabledExtensions::default(),
            idle: IdleState::default(),
            notify: crate::server::notify::NotifyShared::default(),
            pending_qresync: None,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            conn_trace: None,
            pending_cmd_tel: None,
            compress: None,
            compress_active: false,
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

    fn record_compress(&self) {
        ImapServerMetrics::add(&self.metrics.compress, 1);
        if let Some(m) = &self.otel_metrics {
            m.compress();
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
        self.capabilities_as(authenticated)
    }

    fn capabilities_as(&self, authenticated: bool) -> String {
        build_capabilities(&self.config, authenticated, self.tls, self.compress_active)
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
        // The reply is for the client: not the storage pool's own prefix.
        let outcome = outcome.map_err(|e| e.strip_prefix("storage task failed: ").map(str::to_string).unwrap_or(e));
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
                    // exists|recent|uidvalidity|uidnext|highestmodseq|mailboxid[|VANISHED uids]
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
                    let mailboxid = parts.get(5).copied().unwrap_or("");
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
                    if self.config.enable_objectid && !mailboxid.is_empty() {
                        self.send(
                            endpoint,
                            untagged(&format!("OK [MAILBOXID ({mailboxid})] Object id")),
                        );
                    }
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
                    if parts.len() >= 7 && !parts[6].is_empty() {
                        self.send(
                            endpoint,
                            untagged(&format!("VANISHED (EARLIER) {}", parts[6])),
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
                    // The attempt deselected whatever was selected (RFC 9051
                    // §6.3.2), so the connection is authenticated again. The
                    // handler that would have taken over on success is kept:
                    // it serves the authenticated commands as well as the
                    // one it replaced, and dropping it would leave none.
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    self.session = ImapSessionState::Authenticated;
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
            PendingKind::Sort { tag, .. } => match outcome {
                Ok(payload) => {
                    let nums = String::from_utf8_lossy(&payload);
                    self.send(endpoint, untagged(&format!("SORT {nums}")));
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    self.send(endpoint, tagged_ok(&tag, "SORT completed"));
                }
                Err(e) => {
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    self.send(endpoint, tagged_no(&tag, &e));
                }
            },
            PendingKind::Thread { tag, .. } => match outcome {
                Ok(payload) => {
                    // No untagged THREAD line at all when there's nothing
                    // to thread (RFC 5256 §5) — `payload` is empty then.
                    if !payload.is_empty() {
                        let text = String::from_utf8_lossy(&payload);
                        self.send(endpoint, untagged(&format!("THREAD {text}")));
                    }
                    if let Some(h) = selected_handler {
                        self.selected = Some(h);
                    }
                    self.send(endpoint, tagged_ok(&tag, "THREAD completed"));
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

    /// Runs the queued commands in order, up to one that must wait: while a
    /// storage operation is in flight nothing runs, and an APPEND waits for
    /// its body to be on the disk (issue #185).
    fn drain_queue(&mut self, endpoint: &mut dyn Endpoint) {
        while !self.busy.load(Ordering::Relaxed) {
            let Some(front) = self.cmd_queue.front() else {
                break;
            };
            if let Some(spool) = &front.spool {
                let g = spool.lock().unwrap();
                if g.draining || !g.queue.is_empty() {
                    break;
                }
            }
            let Some(QueuedCommand { cmd, spool }) = self.cmd_queue.pop_front() else {
                break;
            };
            if let Some(spool) = spool {
                self.take_append_spool(&spool);
            }
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
        let tel = self.begin_command_telemetry(&cmd.verb);
        self.dispatch_request(endpoint, cmd.tag, cmd.request);
        // Hold telemetry across storage offloads and multi-step AUTHENTICATE.
        if self.busy.load(Ordering::Relaxed) || self.pending_auth.is_some() {
            self.pending_cmd_tel = tel;
        } else if let Some(tel) = tel {
            self.finish_command_telemetry(tel, "ok");
        }
    }

    /// Runs a command whose arguments the lexer has read.
    fn dispatch_request(&mut self, endpoint: &mut dyn Endpoint, tag: String, request: Request) {
        match request {
            Request::Login { user, pass } => self.cmd_login(endpoint, tag, user, pass),
            Request::Authenticate { mechanism, initial_response } => {
                self.cmd_authenticate(endpoint, tag, mechanism, initial_response)
            }
            Request::Select { mailbox, examine, condstore, qresync } => {
                self.cmd_select(endpoint, tag, mailbox, examine, condstore, qresync)
            }
            Request::Create { mailbox } => self.cmd_mgmt_name(endpoint, tag, mailbox, MgmtOp::Create),
            Request::Delete { mailbox } => self.cmd_mgmt_name(endpoint, tag, mailbox, MgmtOp::Delete),
            Request::Subscribe { mailbox } => self.cmd_mgmt_name(endpoint, tag, mailbox, MgmtOp::Subscribe),
            Request::Unsubscribe { mailbox } => self.cmd_mgmt_name(endpoint, tag, mailbox, MgmtOp::Unsubscribe),
            Request::Rename { from, to } => self.cmd_rename(endpoint, tag, from, to),
            Request::Copy { set, mailbox, by_uid } => self.cmd_copy(endpoint, tag, set, mailbox, by_uid),
            Request::Move { set, mailbox, by_uid } => self.cmd_move(endpoint, tag, set, mailbox, by_uid),
            Request::Enable { capabilities } => self.cmd_enable(endpoint, tag, capabilities),
            Request::Compress { mechanism } => self.cmd_compress(endpoint, tag, mechanism),
            Request::GetQuota { root } => self.cmd_getquota(endpoint, tag, root),
            Request::GetQuotaRoot { mailbox } => self.cmd_getquotaroot(endpoint, tag, mailbox),
            Request::Store { set, action, silent, flags, by_uid } => {
                self.cmd_store(endpoint, tag, set, action, silent, flags, by_uid)
            }
            Request::Status { mailbox, items } => self.cmd_status(endpoint, tag, mailbox, items),
            Request::Append { mailbox, flags } => self.cmd_append(endpoint, tag, mailbox, flags),
            Request::Search { criteria, by_uid } => self.cmd_search(endpoint, tag, criteria, by_uid),
            Request::Sort { keys, criteria, by_uid } => self.cmd_sort(endpoint, tag, keys, criteria, by_uid),
            Request::Thread { algorithm, criteria, by_uid } => self.cmd_thread(endpoint, tag, algorithm, criteria, by_uid),
            Request::Capability => {
                let caps = self.capabilities();
                self.send(endpoint, untagged(&format!("CAPABILITY {caps}")));
                self.send(endpoint, tagged_ok(&tag, "CAPABILITY completed"));
            }
            Request::Noop => self.cmd_noop(endpoint, &tag),
            Request::Logout => {
                self.idle.end();
                self.session = ImapSessionState::Logout;
                self.send(endpoint, untagged("BYE Logging out"));
                self.send(endpoint, tagged_ok(&tag, "LOGOUT completed"));
                self.offload_close(false);
                endpoint.close();
            }
            Request::StartTls => self.cmd_starttls(endpoint, &tag),
            Request::Close => self.cmd_close(endpoint, &tag, true),
            Request::Unselect => self.cmd_close(endpoint, &tag, false),
            Request::Namespace => self.cmd_namespace(endpoint, &tag),
            Request::Idle => self.cmd_idle(endpoint, &tag),
            Request::Done => self.send(endpoint, tagged_bad(&tag, "Not IDLEing")),
            Request::GetMetadata { command } => self.cmd_getmetadata(endpoint, tag, command),
            Request::SetMetadata { command } => self.cmd_setmetadata(endpoint, tag, command),
            Request::Notify { state } => self.cmd_notify(endpoint, tag, state),
            Request::SetQuota { root, resources } => self.cmd_setquota(endpoint, tag, root, resources),
            Request::Id { fields } => self.cmd_id(endpoint, tag, fields),
            Request::Expunge { uids } => self.cmd_expunge(endpoint, &tag, uids),
            Request::List { command, lsub } => self.cmd_list(endpoint, tag, command, lsub),
            Request::Fetch { set, items, modifiers, by_uid } => {
                self.cmd_fetch(endpoint, tag, set, items, modifiers, by_uid)
            }
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

    /// Restore `self.selected` after a call into a state-trait `proceed`/
    /// `no` pair whose SPI signature can only carry a `Box<dyn
    /// AuthenticatedHandler>` — used by commands valid from *either*
    /// Authenticated or Selected state (STATUS, GETMETADATA, SETMETADATA),
    /// whose trait signature therefore uses the lowest common denominator
    /// rather than `Box<dyn SelectedHandler>`.
    ///
    /// Without this, a Selected-state call into one of those commands
    /// would silently lose `self.selected` forever (until the next
    /// SELECT): the async completion path only knows how to restore
    /// whichever of `auth_handler` / `selected_handler` its `PendingOpen`
    /// carries, and these commands' `proceed`/`no` only ever hand back an
    /// `AuthenticatedHandler` clone — even when the call actually came
    /// from Selected state. `h` here is the *real* `Box<dyn
    /// SelectedHandler>` the caller took out of `self.selected` before
    /// invoking the command; this overwrites the just-stashed throwaway
    /// clone with it (if the call is still pending an async completion),
    /// or restores it immediately (if nothing is pending — e.g. a custom
    /// handler's `no()` already ran synchronously).
    pub(super) fn restore_selected_after_authenticated_shaped_call(
        &mut self,
        h: Box<dyn SelectedHandler>,
    ) {
        if let Some(p) = self.pending_open.lock().unwrap().as_mut() {
            p.auth_handler = None;
            p.selected_handler = Some(h);
        } else if self.selected.is_none() {
            self.selected = Some(h);
        }
    }

    fn cmd_login(&mut self, endpoint: &mut dyn Endpoint, tag: String, user: String, pass: String) {
        if self.session != ImapSessionState::NotAuthenticated {
            self.send(endpoint, tagged_bad(&tag, "Already authenticated"));
            return;
        }
        if !self.tls && self.config.tls_acceptor.is_some() && !self.config.implicit_tls {
            self.send(
                endpoint,
                tagged_no(&tag, "[PRIVACYREQUIRED] LOGIN disabled on plaintext"),
            );
            return;
        }
        let Some(handle) = self.control_handle.clone() else {
            self.send(endpoint, tagged_no(&tag, "Internal error: no handle"));
            return;
        };
        let store = Arc::clone(&self.config.store);
        let tag = tag.clone();
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

    fn cmd_authenticate(
        &mut self,
        endpoint: &mut dyn Endpoint,
        tag: String,
        mech_name: String,
        initial_response: Option<String>,
    ) {
        if self.session != ImapSessionState::NotAuthenticated {
            self.send(endpoint, tagged_bad(&tag, "Already authenticated"));
            return;
        }
        let Some(mech) = SaslMechanism::from_name(&mech_name) else {
            self.send(endpoint, tagged_no(&tag, "Unsupported mechanism"));
            return;
        };
        if mech.requires_tls() && !self.tls {
            self.send(
                endpoint,
                tagged_no(
                    &tag,
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

        let initial_response = match initial_response.as_deref() {
            // RFC 4959 SASL-IR: a bare "=" is an explicit *empty* initial
            // response, fed straight to the mechanism — not "no response
            // yet" (the `None` arm below, which prompts for one).
            Some("=") => Some(Vec::new()),
            Some(ir) => match base64::decode(ir) {
                Ok(raw) => Some(raw),
                Err(_) => {
                    self.send(endpoint, tagged_no(&tag, "Invalid base64"));
                    return;
                }
            },
            None => None,
        };

        if server.server_first() && initial_response.is_none() {
            // A server-first mechanism (e.g. DIGEST-MD5) must send its
            // challenge before any client response exists to step on —
            // "complete" on this very first step would mean the mechanism
            // authenticated nobody, so treat it as failure, not success
            // (see `AuthCheckOutcome::Step::first_step`).
            self.sasl_step(endpoint, tag, server, None, true);
            return;
        }
        if initial_response.is_none() {
            // A mechanism where the client speaks first, and the client has not
            // (RFC 4959): an empty challenge asks for its first message, which
            // is the next line (RFC 3501 §6.2.2). Stepping the mechanism with
            // nothing would only fail it.
            self.send(endpoint, continuation(""));
            self.pending_auth = Some(PendingAuth { tag, server, completed: None });
            self.lexer.expect_sasl_response();
            return;
        }
        self.sasl_step(endpoint, tag, server, initial_response.as_deref(), false);
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
                        self.pending_auth = Some(PendingAuth { tag, server, completed: None });
                        self.lexer.expect_sasl_response();
                    }
                    SaslServerStep::Complete {
                        username,
                        final_message,
                    } if !first_step => match final_message.filter(|fm| !fm.is_empty()) {
                        Some(fm) => {
                            // Data for the client goes out as a continuation, and
                            // the client answers it with an empty line; only then
                            // is the command complete.
                            self.send(endpoint, continuation(&base64::encode(&fm)));
                            self.pending_auth = Some(PendingAuth { tag, server, completed: Some(username) });
                            self.lexer.expect_sasl_response();
                        }
                        None => self.finish_auth(endpoint, &tag, username),
                    },
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
        // `self.session` hasn't transitioned out of `NotAuthenticated` yet
        // (the view below does that, inside `h.authenticate`) — but
        // authentication has already succeeded by the time `finish_auth`
        // runs, so the capability string embedded in the LOGIN/AUTHENTICATE
        // `OK` response (RFC 9051 §6.2.3, §6.2.2) must reflect the
        // post-auth set, not whatever `self.capabilities()` would compute
        // from the stale pre-auth state.
        let caps = self.capabilities_as(true);
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

    fn cmd_select(
        &mut self,
        endpoint: &mut dyn Endpoint,
        tag: String,
        name: String,
        examine: bool,
        condstore_option: bool,
        qresync_option: Option<(u64, u64)>,
    ) {
        if !self.require_auth(endpoint, &tag) {
            return;
        }
        // Optional (CONDSTORE) / (QRESYNC (...)), already read by the lexer.
        self.pending_qresync = None;
        let mut select_condstore = self.enabled.condstore;
        if condstore_option && self.config.enable_condstore {
            select_condstore = true;
            self.enabled.condstore = true;
        }
        if let Some(resync) = qresync_option {
            if !self.enabled.qresync {
                self.send(
                    endpoint,
                    tagged_bad(&tag, "QRESYNC not enabled (use ENABLE)"),
                );
                return;
            }
            select_condstore = true;
            self.pending_qresync = Some(resync);
        }
        let qresync = self.pending_qresync;
        if let Some(mut h) = self.selected.take() {
            let mut view = SelectView {
                endpoint,
                tag: &tag,
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
                tag: &tag,
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

    fn cmd_mgmt_name(&mut self, endpoint: &mut dyn Endpoint, tag: String, name: String, op: MgmtOp) {
        if !self.require_auth(endpoint, &tag) {
            return;
        }
        self.run_mgmt(
            endpoint,
            &tag,
            name,
            None,
            String::new(),
            String::new(),
            op,
        );
    }

    fn cmd_rename(&mut self, endpoint: &mut dyn Endpoint, tag: String, old: String, new: String) {
        if !self.require_auth(endpoint, &tag) {
            return;
        }
        self.run_mgmt(
            endpoint,
            &tag,
            old,
            Some(new),
            String::new(),
            String::new(),
            MgmtOp::Rename,
        );
    }

    fn cmd_list(&mut self, endpoint: &mut dyn Endpoint, tag: String, parsed: ListCommand, lsub: bool) {
        if !self.require_auth(endpoint, &tag) {
            return;
        }
        if lsub {
            self.run_mgmt(endpoint, &tag, String::new(), None, parsed.reference, parsed.pattern, MgmtOp::Lsub);
            return;
        }
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
                &tag,
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
        self.run_list_ext(endpoint, &tag, parsed, subscribed);
    }

    fn cmd_fetch(
        &mut self,
        endpoint: &mut dyn Endpoint,
        tag: String,
        set: MessageSet,
        mut items: Vec<FetchItem>,
        modifiers: FetchModifiers,
        by_uid: bool,
    ) {
        if !self.require_selected(endpoint, &tag) {
            return;
        }
        if items.iter().any(|i| matches!(i, FetchItem::ModSeq)) && self.config.enable_condstore {
            // Asking for MODSEQ is using CONDSTORE (RFC 7162 §3.1).
            self.enabled.condstore = true;
        }
        if modifiers.changed_since.is_some() && !self.enabled.condstore {
            // Implicitly enable CONDSTORE when CHANGEDSINCE is used (RFC 7162).
            if self.config.enable_condstore {
                self.enabled.condstore = true;
            }
        }
        if self.enabled.condstore
            && !items
                .iter()
                .any(|i| matches!(i, FetchItem::ModSeq))
        {
            items.push(FetchItem::ModSeq);
        }
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = FetchView {
            endpoint,
            tag: &tag,
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

    // Each parameter is an independent piece of per-command dispatch context.
    #[allow(clippy::too_many_arguments)]
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

    fn cmd_append(&mut self, endpoint: &mut dyn Endpoint, tag: String, name: String, flags: BTreeSetFlags) {
        if !self.require_auth(endpoint, &tag) {
            // Refused (a pipelined login failed): the body spooled for it goes too.
            self.pending_append_error = None;
            if let Some(path) = self.pending_append_path.take() {
                let _ = std::fs::remove_file(path);
            }
            return;
        }
        if let Some(err) = self.pending_append_error.take() {
            if let Some(path) = self.pending_append_path.take() {
                let _ = std::fs::remove_file(path);
            }
            self.send(endpoint, tagged_no(&tag, &format!("Could not stage message: {err}")));
            return;
        }
        let Some(body_path) = self.pending_append_path.take() else {
            self.send(endpoint, tagged_bad(&tag, "APPEND requires a message literal"));
            return;
        };
        let keywords = flags.keywords;
        let flags = flags.flags;
        let internal_date: Option<SystemTime> = None;
        if let Some(mut h) = self.selected.take() {
            let mut view = AppendView {
                endpoint,
                tag: &tag,
                mailbox: name.clone(),
                body_path: Some(body_path),
                flags: flags.clone(),
                keywords: keywords.clone(),
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
                tag: &tag,
                mailbox: name.clone(),
                body_path: Some(body_path),
                flags: flags.clone(),
                keywords: keywords.clone(),
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

    fn cmd_store(
        &mut self,
        endpoint: &mut dyn Endpoint,
        tag: String,
        set: MessageSet,
        action: StoreAction,
        silent: bool,
        flist: BTreeSetFlags,
        by_uid: bool,
    ) {
        if !self.require_selected(endpoint, &tag) {
            return;
        }
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = StoreView {
            condstore: self.enabled.condstore,
            endpoint,
            tag: &tag,
            set: set.clone(),
            by_uid,
            selected: &mut self.selected,
            bundle: &self.bundle,
            runtime: &self.runtime,
            busy: &self.busy,
            control_handle: &self.control_handle,
            pending_open: &self.pending_open,
        };
        let request = StoreRequest {
            action,
            flags: flist.flags,
            keywords: flist.keywords,
            silent,
        };
        let g = self.bundle.lock().unwrap();
        if let Some(mb) = g.mailbox.as_ref() {
            h.store(&mut view, mb.as_ref(), &set, &request, by_uid);
        }
        drop(g);
        if self.selected.is_none() && self.pending_open.lock().unwrap().is_none() {
            self.selected = Some(h);
        }
    }

    fn cmd_search(&mut self, endpoint: &mut dyn Endpoint, tag: String, criteria: SearchCriteria, by_uid: bool) {
        if !self.require_selected(endpoint, &tag) {
            return;
        }
        if uses_modseq(&criteria) && self.config.enable_condstore {
            // Searching on MODSEQ is using CONDSTORE (RFC 7162 §3.1).
            self.enabled.condstore = true;
        }
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = SearchView {
            endpoint,
            tag: &tag,
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

    fn cmd_sort(
        &mut self,
        endpoint: &mut dyn Endpoint,
        tag: String,
        sort_criteria: Vec<SortCriterion>,
        search_criteria: SearchCriteria,
        by_uid: bool,
    ) {
        if !self.require_selected(endpoint, &tag) {
            return;
        }
        if !self.config.enable_sort {
            self.send(endpoint, tagged_bad(&tag, "SORT not available"));
            return;
        }
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = SortView {
            endpoint,
            tag: &tag,
            sort_criteria: sort_criteria.clone(),
            search_criteria: search_criteria.clone(),
            by_uid,
            selected: &mut self.selected,
            bundle: &self.bundle,
            runtime: &self.runtime,
            busy: &self.busy,
            control_handle: &self.control_handle,
            pending_open: &self.pending_open,
        };
        let sort_keys: Vec<crate::server::sort::SortKey> =
            sort_criteria.iter().map(|c| c.key).collect();
        let g = self.bundle.lock().unwrap();
        if let Some(mb) = g.mailbox.as_ref() {
            h.sort(&mut view, mb.as_ref(), &sort_keys, &search_criteria, by_uid);
        }
        drop(g);
        if self.selected.is_none() && self.pending_open.lock().unwrap().is_none() {
            self.selected = Some(h);
        }
    }

    fn cmd_thread(
        &mut self,
        endpoint: &mut dyn Endpoint,
        tag: String,
        algorithm: ThreadAlgorithm,
        search_criteria: SearchCriteria,
        by_uid: bool,
    ) {
        if !self.require_selected(endpoint, &tag) {
            return;
        }
        let enabled = match algorithm {
            ThreadAlgorithm::OrderedSubject => self.config.enable_thread_ordered_subject,
            ThreadAlgorithm::References => self.config.enable_thread_references,
        };
        if !enabled {
            self.send(
                endpoint,
                tagged_bad(&tag, "THREAD algorithm not available"),
            );
            return;
        }
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = ThreadView {
            endpoint,
            tag: &tag,
            algorithm,
            search_criteria: search_criteria.clone(),
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
            h.thread(&mut view, mb.as_ref(), algorithm, &search_criteria, by_uid);
        }
        drop(g);
        if self.selected.is_none() && self.pending_open.lock().unwrap().is_none() {
            self.selected = Some(h);
        }
    }

    fn cmd_copy(&mut self, endpoint: &mut dyn Endpoint, tag: String, set: MessageSet, dest: String, by_uid: bool) {
        if !self.require_selected(endpoint, &tag) {
            return;
        }
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = CopyView {
            endpoint,
            tag: &tag,
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
        // The body of an APPEND arrives (and is spooled) before the command is
        // dispatched. Until the client has logged in it is read and dropped,
        // so an unauthenticated connection cannot make the server write to
        // disk; the command is then refused as usual. (A login that is still
        // being checked, or is queued ahead of this command, may yet succeed,
        // so a pipelined LOGIN and APPEND keep working.)
        let may_log_in_first = self.busy.load(Ordering::Relaxed) || self.pending_auth.is_some() || !self.cmd_queue.is_empty();
        if !matches!(self.session, ImapSessionState::Authenticated | ImapSessionState::Selected) && !may_log_in_first {
            return;
        }
        let mut g = self.append_spool.lock().unwrap();
        if g.error.is_some() {
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

    /// The APPEND whose literal has just been read is complete as far as
    /// the reader is concerned: its spool is sealed (writes already queued
    /// for it carry on into it) and the next literal starts a fresh one.
    fn seal_append_spool(&mut self) -> Arc<Mutex<AppendSpoolState>> {
        std::mem::replace(&mut self.append_spool, Arc::new(Mutex::new(AppendSpoolState::default())))
    }

    /// The sealed `spool` has drained: its path and first error become
    /// `pending_append_path` / `pending_append_error`, ready for `cmd_append`.
    fn take_append_spool(&mut self, spool: &Arc<Mutex<AppendSpoolState>>) {
        let mut g = spool.lock().unwrap();
        if let Some(f) = g.file.take() {
            let _ = f.sync_all();
        }
        self.pending_append_path = g.path.take();
        self.pending_append_error = g.error.take();
    }

    fn feed_auth_line(&mut self, endpoint: &mut dyn Endpoint, line: &[u8]) {
        let Some(PendingAuth { tag, server, completed }) = self.pending_auth.take() else {
            return;
        };
        if line == b"*" {
            self.send(endpoint, tagged_bad(&tag, "Authentication cancelled"));
            return;
        }
        if let Some(username) = completed {
            if line.is_empty() {
                self.finish_auth(endpoint, &tag, username);
            } else {
                self.send(endpoint, tagged_bad(&tag, "Expected an empty response"));
            }
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

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            let Some(mut layer) = self.compress.take() else {
                self.receive_inner(endpoint, data);
                return;
            };
            // RFC 4978: once negotiated, every byte in both directions is raw
            // DEFLATE for the rest of the session — inflate what just arrived,
            // then let `receive_inner` process it exactly as it would an
            // uncompressed connection, through a `CompressingEndpoint` that
            // transparently deflates every `send()` it forwards.
            let result = layer.inflate(data);
            *data = &[];
            match result {
                Ok(plaintext) => {
                    let mut cursor: &[u8] = &plaintext;
                    {
                        let mut wrapped = CompressingEndpoint::new(endpoint, &mut layer);
                        self.receive_inner(&mut wrapped, &mut cursor);
                    }
                    self.compress = Some(layer);
                }
                Err(_) => {
                    // Malformed compressed data: nothing safe to recover to.
                    self.compress = Some(layer);
                    endpoint.close();
                }
            }
        });
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

impl ImapControlHandler {
    fn receive_inner(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.sync_pending(endpoint);
        self.sync_pending_auth_check(endpoint);
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
                    // before its Command event - see `codec::feed_literal`'s
                    // `LiteralPhase::Append` arm - so the spool sealed here is
                    // exactly the one that belongs to `cmd`. State gating
                    // (rejecting Selected commands when not selected) happens
                    // inside dispatch; every command goes through the queue so
                    // that none runs ahead of one that is waiting.
                    let spool = matches!(cmd.request, Request::Append { .. }).then(|| self.seal_append_spool());
                    self.cmd_queue.push_back(QueuedCommand { cmd, spool });
                    self.drain_queue(endpoint);
                }
            }
        }
        self.sync_pending(endpoint);
        self.sync_pending_auth_check(endpoint);
        self.drain_queue(endpoint);
    }
}

/// Does a search key anywhere in `criteria` ask about modification sequences?
fn uses_modseq(criteria: &SearchCriteria) -> bool {
    match criteria {
        SearchCriteria::ModSeq(_) => true,
        SearchCriteria::And(keys) => keys.iter().any(uses_modseq),
        SearchCriteria::Or(a, b) => uses_modseq(a) || uses_modseq(b),
        SearchCriteria::Not(key) => uses_modseq(key),
        _ => false,
    }
}

/// A command read from the client and waiting its turn. An APPEND carries the
/// spool its body is being written to.
struct QueuedCommand {
    cmd: ImapCommand,
    spool: Option<Arc<Mutex<AppendSpoolState>>>,
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
            let poke_handle = cb_handle.clone();
            // The next write is started (or `draining` cleared) before the
            // poke, so that when the handler looks at the spool in answer to
            // it, a spool with nothing left to write is seen to be done.
            if ok {
                drain_next_append_chunk(cb_state, cb_runtime, cb_handle);
            }
            poke_handle.with_endpoint(|ep| {
                // Lets `ImapControlHandler::drain_queue` (issue #185) run an
                // APPEND promptly once this was the last outstanding write,
                // instead of waiting for the client's next input to trigger
                // another `receive()`.
                ep.poke_handler();
            });
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
mod session_tests;

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
        // (An APPEND body is only spooled for a client that has logged in.)
        h.session = ImapSessionState::Authenticated;
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

        let spool = h.seal_append_spool();
        assert!(
            wait_for(
                || {
                    let g = spool.lock().unwrap();
                    !g.draining && g.queue.is_empty()
                },
                3000
            ),
            "the spool must drain once every offloaded write lands"
        );
        h.take_append_spool(&spool);
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
        let spool = h.seal_append_spool();
        h.take_append_spool(&spool);
        assert!(h.pending_append_path.is_none());
        assert!(h.pending_append_error.is_none());
    }

    #[test]
    fn command_after_draining_literal_is_deferred_then_dispatched_in_order() {
        let mut h = test_handler();
        let mut ep = NoopEndpoint;

        h.handle_append_chunk(b"hello world");
        let append_cmd = ImapCommand::new(
            "a1",
            "APPEND",
            crate::server::grammar::Request::Append { mailbox: "INBOX".into(), flags: Default::default() },
        );
        // Mirrors `receive()`'s `LexEvent::Command` arm.
        let spool = Some(h.seal_append_spool());
        h.cmd_queue.push_back(QueuedCommand { cmd: append_cmd, spool });
        h.drain_queue(&mut ep);

        // A further pipelined command must queue behind the APPEND, not run
        // ahead of it.
        let noop_cmd = ImapCommand::new("a2", "NOOP", crate::server::grammar::Request::Noop);
        h.cmd_queue.push_back(QueuedCommand { cmd: noop_cmd, spool: None });
        h.drain_queue(&mut ep);
        if h.cmd_queue.iter().any(|q| q.cmd.tag == "a1") {
            assert!(
                h.cmd_queue.iter().any(|q| q.cmd.tag == "a2"),
                "a2 must wait behind the still-draining APPEND, not dispatch early"
            );
        }

        assert!(
            wait_for(
                || {
                    h.drain_queue(&mut ep);
                    h.cmd_queue.is_empty() && !h.busy.load(Ordering::Relaxed)
                },
                3000
            ),
            "the APPEND and the command behind it must both run once the body is on disk"
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
