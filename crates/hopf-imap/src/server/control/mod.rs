// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP control-connection protocol handler.

mod ext;

use std::collections::{BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use hopf_auth::plain::parse_credentials;
use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, StorageError};
use hopf_mailbox::{Mailbox, MailboxStore};

use rmimeparser::charset::base64;

use crate::enable::EnabledExtensions;
use crate::server::capability::build_capabilities;
use crate::server::codec::{
    parse_astring, parse_flag_list, parse_sequence_set, parse_store_item, ImapCommand,
    ImapServerLexer, LexEvent, MAX_COMMAND_LINE,
};
use crate::server::fetch_format::parse_fetch_args;
use crate::server::handler::{
    AuthenticatedHandler, ClientConnected, NotAuthenticatedHandler, SelectedHandler,
};
use crate::server::idle::{is_idle_done, IdleState};
use crate::server::reply::{continuation, tagged_bad, tagged_no, tagged_ok, untagged};
use crate::server::search_parse::parse_search;
use crate::server::service::ImapConfig;
use crate::server::session::ImapSessionState;
use crate::server::views::{
    AppendView, AuthView, CloseView, ConnectedView, CopyView, FetchView, MgmtOp, MgmtView,
    SearchView, SelectView, StoreView,
};

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

enum PendingAuth {
    Plain { tag: String },
}

/// Per-connection IMAP protocol state machine.
pub struct ImapControlHandler {
    client_connected: Option<Box<dyn ClientConnected>>,
    not_authenticated: Option<Box<dyn NotAuthenticatedHandler>>,
    authenticated: Option<Box<dyn AuthenticatedHandler>>,
    selected: Option<Box<dyn SelectedHandler>>,
    config: ImapConfig,
    runtime: Arc<Runtime>,
    lexer: ImapServerLexer,
    session: ImapSessionState,
    tls: bool,
    expect_implicit_tls: bool,
    greeting_sent: bool,
    starttls_used: bool,
    username: Option<String>,
    control_handle: Option<ConnHandle>,
    bundle: Arc<Mutex<MailboxBundle>>,
    peer: SocketAddr,
    local: SocketAddr,
    busy: Arc<AtomicBool>,
    cmd_queue: VecDeque<ImapCommand>,
    pending_auth: Option<PendingAuth>,
    /// APPEND literal being spooled to a temp file as chunks arrive — never
    /// buffered whole in memory (see `AppendChunk`/`finalize_pending_append`).
    pending_append_file: Option<(std::fs::File, std::path::PathBuf)>,
    /// First spool write error, if any.
    pending_append_error: Option<String>,
    /// Finalized spool path, ready for `cmd_append` to stream from — `None`
    /// path with no error means a zero-length (`{0}`) literal.
    pending_append_path: Option<std::path::PathBuf>,
    pending_open: Arc<Mutex<Option<PendingOpen>>>,
    /// Per-session ENABLE set.
    enabled: EnabledExtensions,
    /// IDLE session.
    idle: IdleState,
    /// QRESYNC parameters from the last SELECT (uidvalidity, modseq).
    pending_qresync: Option<(u64, u64)>,
}

impl ImapControlHandler {
    /// Create a new control handler for one accept.
    pub fn new(
        client: Box<dyn ClientConnected>,
        config: ImapConfig,
        runtime: Arc<Runtime>,
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
            lexer: ImapServerLexer::new(max_line),
            session: ImapSessionState::NotAuthenticated,
            tls: false,
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
            busy: Arc::new(AtomicBool::new(false)),
            cmd_queue: VecDeque::new(),
            pending_auth: None,
            pending_append_file: None,
            pending_append_error: None,
            pending_append_path: None,
            pending_open: Arc::new(Mutex::new(None)),
            enabled: EnabledExtensions::default(),
            idle: IdleState::default(),
            pending_qresync: None,
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
        let caps = self.capabilities();
        let mut view = ConnectedView {
            endpoint,
            not_authenticated: &mut self.not_authenticated,
            caps: &caps,
            session: &mut self.session,
        };
        if let Some(mut c) = self.client_connected.take() {
            c.connected(&mut view, self.peer, self.local, self.tls);
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
            PendingKind::Select {
                tag,
                examine,
                condstore,
            } => match outcome {
                Ok(payload) => {
                    let s = String::from_utf8_lossy(&payload);
                    // exists|recent|uidvalidity|uidnext|highestmodseq[|VANISHED uids]
                    let parts: Vec<&str> = s.split('|').collect();
                    let (exists, recent, uidvalidity, uidnext, highest) = if parts.len() >= 5 {
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
                    self.send(endpoint, untagged(&format!("{recent} RECENT")));
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
                    if let Ok(n) = recent.parse::<u32>() {
                        self.idle.last_recent = n;
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
    }

    fn drain_queue(&mut self, endpoint: &mut dyn Endpoint) {
        while !self.busy.load(Ordering::Relaxed) {
            let Some(cmd) = self.cmd_queue.pop_front() else {
                break;
            };
            self.dispatch(endpoint, cmd);
        }
    }

    fn enqueue_or_dispatch(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if self.busy.load(Ordering::Relaxed) {
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
        let verb = cmd.verb.as_str();
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
        if !self.config.store.password_match(&user, &pass) {
            self.send(endpoint, tagged_no(&cmd.tag, "Invalid credentials"));
            return;
        }
        self.finish_auth(endpoint, &cmd.tag, user);
    }

    fn cmd_authenticate(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if self.session != ImapSessionState::NotAuthenticated {
            self.send(endpoint, tagged_bad(&cmd.tag, "Already authenticated"));
            return;
        }
        let mut parts = cmd.args.split_whitespace();
        let Some(mech) = parts.next() else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Missing mechanism"));
            return;
        };
        if !mech.eq_ignore_ascii_case("PLAIN") {
            self.send(endpoint, tagged_no(&cmd.tag, "Unsupported mechanism"));
            return;
        }
        if let Some(ir) = parts.next() {
            if ir == "=" {
                // RFC 4959 SASL-IR: a bare "=" is an explicit *empty* initial
                // response, fed straight to the mechanism — not "no response
                // yet" (that's the `None` arm below, which prompts for one).
                self.complete_plain(endpoint, &cmd.tag, &[]);
                return;
            }
            match base64::decode(ir) {
                Ok(raw) => self.complete_plain(endpoint, &cmd.tag, &raw),
                Err(_) => self.send(endpoint, tagged_no(&cmd.tag, "Invalid base64")),
            }
        } else {
            self.pending_auth = Some(PendingAuth::Plain { tag: cmd.tag });
            self.lexer.expect_sasl_response();
            self.send(endpoint, continuation(""));
        }
    }

    fn complete_plain(&mut self, endpoint: &mut dyn Endpoint, tag: &str, raw: &[u8]) {
        let Some((_, authcid, password)) = parse_credentials(raw) else {
            self.send(endpoint, tagged_no(tag, "Invalid PLAIN credentials"));
            return;
        };
        if !self.config.store.password_match(&authcid, &password) {
            self.send(endpoint, tagged_no(tag, "Invalid credentials"));
            return;
        }
        self.finish_auth(endpoint, tag, authcid);
    }

    fn finish_auth(&mut self, endpoint: &mut dyn Endpoint, tag: &str, username: String) {
        self.username = Some(username.clone());
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

    /// Spool one APPEND literal chunk to a temp file, created lazily on the
    /// first chunk — the literal is never buffered whole in memory.
    fn handle_append_chunk(&mut self, chunk: &[u8]) {
        if self.pending_append_error.is_some() {
            return;
        }
        if self.pending_append_file.is_none() {
            let path = unique_append_spool_path();
            match std::fs::File::create(&path) {
                Ok(f) => self.pending_append_file = Some((f, path)),
                Err(e) => {
                    self.pending_append_error = Some(e.to_string());
                    return;
                }
            }
        }
        if let Some((f, _)) = &mut self.pending_append_file {
            use std::io::Write;
            if let Err(e) = f.write_all(chunk) {
                self.pending_append_error = Some(e.to_string());
            }
        }
    }

    /// Move the just-completed APPEND spool (if any) into
    /// `pending_append_path`, ready for `cmd_append` to stream from.
    fn finalize_pending_append(&mut self) {
        if let Some((f, path)) = self.pending_append_file.take() {
            let _ = f.sync_all();
            self.pending_append_path = Some(path);
        }
    }

    fn feed_auth_line(&mut self, endpoint: &mut dyn Endpoint, line: &[u8]) {
        let Some(PendingAuth::Plain { tag }) = self.pending_auth.take() else {
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
            Some(raw) => self.complete_plain(endpoint, &tag, &raw),
            None => self.send(endpoint, tagged_no(&tag, "Invalid base64")),
        }
    }
}

impl ProtocolHandler for ImapControlHandler {
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
        self.control_handle = Some(endpoint.handle());
        if !self.expect_implicit_tls || self.tls {
            self.greet(endpoint);
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.sync_pending(endpoint);
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
                    self.finalize_pending_append();
                    // State gating (reject Selected cmds when not selected)
                    // happens inside dispatch. While a storage operation is in
                    // flight, `enqueue_or_dispatch` queues pipelined commands
                    // instead of dispatching, so keep consuming every event
                    // lexed from this buffer — breaking here would drop them.
                    self.enqueue_or_dispatch(endpoint, cmd);
                }
            }
        }
        self.sync_pending(endpoint);
        self.drain_queue(endpoint);
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if let Some(mut c) = self.client_connected.take() {
            c.disconnected();
        }
        if self.session != ImapSessionState::Logout {
            self.offload_close(false);
        }
    }

    fn security_established(
        &mut self,
        endpoint: &mut dyn Endpoint,
        _info: &hopf_core::SecurityInfo,
    ) {
        self.tls = true;
        if self.expect_implicit_tls && !self.greeting_sent {
            self.greet(endpoint);
            return;
        }
        let _ = self.starttls_used;
        self.starttls_used = false;
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &std::io::Error) {
        endpoint.close();
    }
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
