// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Storage-backed state views for IMAP command policy callbacks.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use hopf_core::{ConnHandle, Endpoint, Runtime, StorageError};
use hopf_mailbox::{
    Flag, Mailbox, MailboxFactory, MailboxInfo, MailboxStore, MessageSet, SearchCriteria,
};

use crate::server::control::{MailboxBundle, PendingOpen};
use crate::server::fetch_format::{
    fetch_sets_seen, format_fetch_attrs, push_fetch_attrs, FetchItem,
};
use crate::server::handler::{
    AppendState, AuthenticateState, AuthenticatedHandler, CloseState, ConnectedState, CopyState,
    CreateState, DeleteState, ExpungeState, FetchState, ListState, MoveState,
    NotAuthenticatedHandler, RenameState, SearchState, SelectState, SelectedHandler, StatusState,
    StoreAction, StoreState, SubscribeState,
};
use crate::server::reply::{format_list_attrs, quote_astring, tagged_no, tagged_ok, untagged};
use crate::server::session::ImapSessionState;
use crate::server::status_items::StatusItem;
use crate::server::uidplus::{format_appenduid, format_copyuid};

/// Shared offload helpers.
pub(crate) fn begin_busy(endpoint: &mut dyn Endpoint, busy: &Arc<AtomicBool>) {
    busy.store(true, Ordering::Relaxed);
    endpoint.pause_read();
}

pub(crate) fn end_busy(endpoint: &mut dyn Endpoint, busy: &Arc<AtomicBool>) {
    busy.store(false, Ordering::Relaxed);
    endpoint.resume_read();
    // Re-enter the control handler so the deferred reply is emitted and any
    // commands queued while busy are dispatched — the peer may be waiting for
    // this reply and send nothing further.
    endpoint.poke_handler();
}

pub(crate) struct ConnectedView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub not_authenticated: &'a mut Option<Box<dyn NotAuthenticatedHandler>>,
    pub caps: &'a str,
    pub session: &'a mut ImapSessionState,
    pub username: &'a mut Option<String>,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
    pub factory: Arc<dyn MailboxFactory>,
}

impl ConnectedState for ConnectedView<'_> {
    fn accept_connection(&mut self, greeting: &str, handler: Box<dyn NotAuthenticatedHandler>) {
        *self.not_authenticated = Some(handler);
        *self.session = ImapSessionState::NotAuthenticated;
        self.endpoint.send(&untagged(&format!(
            "OK [CAPABILITY {}] {greeting}",
            self.caps
        )));
    }

    fn accept_preauth(
        &mut self,
        greeting: &str,
        username: &str,
        handler: Box<dyn AuthenticatedHandler>,
    ) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint
                .send(&untagged("BYE Internal error: no handle"));
            self.endpoint.close();
            return;
        };
        *self.username = Some(username.to_string());
        let bundle = Arc::clone(self.bundle);
        let factory = Arc::clone(&self.factory);
        let user = username.to_string();
        let caps = self.caps.to_string();
        let greet = greeting.to_string();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: Some(handler),
            selected_handler: None,
            outcome: None,
            kind: crate::server::control::PendingKind::Preauth {
                caps,
                greeting: greet,
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut store = factory.create_store();
                store.open(&user).map_err(|e| e.to_string())?;
                bundle.lock().unwrap().store = Some(store);
                Ok(())
            },
            move |result: Result<(), StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        p.outcome = Some(match result {
                            Ok(()) => Ok(Vec::new()),
                            Err(e) => Err(e.to_string()),
                        });
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn reject_connection(&mut self, message: &str) {
        self.endpoint.send(&untagged(&format!("BYE {message}")));
        self.endpoint.close();
    }
}

pub(crate) struct AuthView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub not_authenticated: &'a mut Option<Box<dyn NotAuthenticatedHandler>>,
    pub authenticated: &'a mut Option<Box<dyn AuthenticatedHandler>>,
    pub session: &'a mut ImapSessionState,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
    pub caps: String,
    pub username: String,
    pub factory: Arc<dyn MailboxFactory>,
}

impl AuthenticateState for AuthView<'_> {
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint
                .send(&tagged_no(self.tag, "Internal error: no handle"));
            *self.not_authenticated = Some(Box::new(DummyNotAuth));
            let _ = handler;
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let username = self.username.clone();
        let factory = Arc::clone(&self.factory);
        let tag = self.tag.to_string();
        let caps = self.caps.clone();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: Some(handler),
            selected_handler: None,
            outcome: None,
            kind: crate::server::control::PendingKind::Auth {
                tag: tag.clone(),
                caps,
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut store = factory.create_store();
                store.open(&username).map_err(|e| e.to_string())?;
                bundle.lock().unwrap().store = Some(store);
                Ok(())
            },
            move |result: Result<(), StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        p.outcome = Some(match result {
                            Ok(()) => Ok(Vec::new()),
                            Err(e) => Err(e.to_string()),
                        });
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn accept_opened(
        &mut self,
        store: Box<dyn MailboxStore>,
        handler: Box<dyn AuthenticatedHandler>,
    ) {
        self.bundle.lock().unwrap().store = Some(store);
        *self.authenticated = Some(handler);
        *self.session = ImapSessionState::Authenticated;
        *self.not_authenticated = None;
        self.endpoint.send(&tagged_ok(
            self.tag,
            &format!("[CAPABILITY {}] LOGIN completed", self.caps),
        ));
    }

    fn reject(&mut self, message: &str, handler: Box<dyn NotAuthenticatedHandler>) {
        *self.not_authenticated = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

/// Placeholder when proceed fails before stashing the real handler.
struct DummyNotAuth;
impl NotAuthenticatedHandler for DummyNotAuth {
    fn authenticate(
        &mut self,
        _state: &mut dyn AuthenticateState,
        _username: &str,
        _factory: &dyn MailboxFactory,
    ) {
    }
}

pub(crate) struct SelectView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub name: String,
    pub examine: bool,
    pub condstore: bool,
    pub qresync: Option<(u64, u64)>,
    pub authenticated: &'a mut Option<Box<dyn AuthenticatedHandler>>,
    pub selected: &'a mut Option<Box<dyn SelectedHandler>>,
    #[allow(dead_code)]
    pub session: &'a mut ImapSessionState,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
}

impl SelectState for SelectView<'_> {
    fn proceed(&mut self, handler: Box<dyn SelectedHandler>) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint.send(&tagged_no(self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let name = self.name.clone();
        let examine = self.examine;
        let condstore = self.condstore;
        let qresync = self.qresync;
        let tag = self.tag.to_string();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: None,
            selected_handler: Some(handler),
            outcome: None,
            kind: crate::server::control::PendingKind::Select {
                tag: tag.clone(),
                examine,
                condstore,
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut g = bundle.lock().unwrap();
                if let Some(mut mb) = g.mailbox.take() {
                    let _ = mb.close(false);
                }
                let store = g.store.as_mut().ok_or_else(|| "no store".to_string())?;
                let mb = store
                    .open_mailbox(&name, examine)
                    .map_err(|e| e.to_string())?;
                let status = mb.status().map_err(|e| e.to_string())?;
                let mut vanished = String::new();
                // QRESYNC: only emit VANISHED (EARLIER) when the backend actually
                // reports expunged UIDs — never invent vanished history.
                if let Some((uv, modseq)) = qresync {
                    if uv == status.uid_validity && status.highest_modseq > 0 {
                        let uids = mb.expunged_since(modseq).unwrap_or_default();
                        if !uids.is_empty() {
                            vanished = uids
                                .iter()
                                .map(|u| u.to_string())
                                .collect::<Vec<_>>()
                                .join(",");
                        }
                    }
                }
                g.mailbox = Some(mb);
                g.read_only = examine;
                let mut payload = format!(
                    "{}|{}|{}|{}|{}",
                    status.messages,
                    status.recent,
                    status.uid_validity,
                    status.uid_next,
                    status.highest_modseq
                );
                if !vanished.is_empty() {
                    payload.push('|');
                    payload.push_str(&vanished);
                }
                Ok(payload.into_bytes())
            },
            move |result: Result<Vec<u8>, StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        p.outcome = Some(result.map_err(|e| e.to_string()));
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>) {
        *self.authenticated = Some(handler);
        *self.selected = None;
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

pub(crate) struct CloseView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub expunge: bool,
    #[allow(dead_code)]
    pub authenticated: &'a mut Option<Box<dyn AuthenticatedHandler>>,
    pub selected: &'a mut Option<Box<dyn SelectedHandler>>,
    #[allow(dead_code)]
    pub session: &'a mut ImapSessionState,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
    #[allow(dead_code)]
    pub next_auth: Option<Box<dyn AuthenticatedHandler>>,
}

impl CloseState for CloseView<'_> {
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint.send(&tagged_no(self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let tag = self.tag.to_string();
        let expunge = self.expunge;
        let ok = if expunge {
            "CLOSE completed".to_string()
        } else {
            "UNSELECT completed".to_string()
        };
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: Some(handler),
            selected_handler: None,
            outcome: None,
            kind: crate::server::control::PendingKind::Close {
                tag: tag.clone(),
                ok,
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut g = bundle.lock().unwrap();
                if let Some(mut mb) = g.mailbox.take() {
                    mb.close(expunge).map_err(|e| e.to_string())?;
                }
                g.read_only = false;
                Ok(Vec::new())
            },
            move |result: Result<Vec<u8>, StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        p.outcome = Some(result.map_err(|e| e.to_string()));
                    }
                    end_busy(ep, &busy);
                });
            },
        );
        *self.selected = None;
    }

    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>) {
        *self.selected = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

macro_rules! simple_mgmt_proceed {
    ($self:ident, $handler:ident, $kind:expr, $op:expr) => {{
        let Some(handle) = $self.control_handle.clone() else {
            $self.endpoint.send(&tagged_no($self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone($self.bundle);
        let busy = Arc::clone($self.busy);
        let pending = Arc::clone($self.pending_open);
        let op = $op;
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: Some($handler),
            selected_handler: None,
            outcome: None,
            kind: $kind,
        });
        begin_busy($self.endpoint, $self.busy);
        $self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut g = bundle.lock().unwrap();
                let store = g.store.as_mut().ok_or_else(|| "no store".to_string())?;
                op(store)?;
                Ok(Vec::new())
            },
            move |result: Result<Vec<u8>, StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        p.outcome = Some(result.map_err(|e| e.to_string()));
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }};
}

pub(crate) struct MgmtView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub name: String,
    pub name2: Option<String>,
    pub reference: String,
    pub pattern: String,
    pub op: MgmtOp,
    pub authenticated: &'a mut Option<Box<dyn AuthenticatedHandler>>,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
}

#[derive(Clone, Copy)]
pub(crate) enum MgmtOp {
    Create,
    Delete,
    Rename,
    Subscribe,
    Unsubscribe,
    List,
    Lsub,
}

impl CreateState for MgmtView<'_> {
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>) {
        let name = self.name.clone();
        simple_mgmt_proceed!(
            self,
            handler,
            crate::server::control::PendingKind::Mgmt {
                tag: self.tag.to_string(),
                ok: "CREATE completed".into(),
            },
            move |store: &mut Box<dyn MailboxStore>| {
                store.create_mailbox(&name).map_err(|e| e.to_string())
            }
        );
    }
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>) {
        *self.authenticated = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

impl DeleteState for MgmtView<'_> {
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>) {
        let name = self.name.clone();
        simple_mgmt_proceed!(
            self,
            handler,
            crate::server::control::PendingKind::Mgmt {
                tag: self.tag.to_string(),
                ok: "DELETE completed".into(),
            },
            move |store: &mut Box<dyn MailboxStore>| {
                store.delete_mailbox(&name).map_err(|e| e.to_string())
            }
        );
    }
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>) {
        *self.authenticated = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

impl RenameState for MgmtView<'_> {
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>) {
        let old = self.name.clone();
        let new = self.name2.clone().unwrap_or_default();
        simple_mgmt_proceed!(
            self,
            handler,
            crate::server::control::PendingKind::Mgmt {
                tag: self.tag.to_string(),
                ok: "RENAME completed".into(),
            },
            move |store: &mut Box<dyn MailboxStore>| {
                store.rename_mailbox(&old, &new).map_err(|e| e.to_string())
            }
        );
    }
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>) {
        *self.authenticated = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

impl SubscribeState for MgmtView<'_> {
    fn proceed(&mut self, handler: Box<dyn AuthenticatedHandler>) {
        let name = self.name.clone();
        let unsub = matches!(self.op, MgmtOp::Unsubscribe);
        let ok = if unsub {
            "UNSUBSCRIBE completed"
        } else {
            "SUBSCRIBE completed"
        };
        simple_mgmt_proceed!(
            self,
            handler,
            crate::server::control::PendingKind::Mgmt {
                tag: self.tag.to_string(),
                ok: ok.into(),
            },
            move |store: &mut Box<dyn MailboxStore>| {
                if unsub {
                    store.unsubscribe(&name).map_err(|e| e.to_string())
                } else {
                    store.subscribe(&name).map_err(|e| e.to_string())
                }
            }
        );
    }
    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>) {
        *self.authenticated = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

impl ListState for MgmtView<'_> {
    fn proceed(&mut self, subscribed: bool, handler: Box<dyn AuthenticatedHandler>) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint.send(&tagged_no(self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let reference = self.reference.clone();
        let pattern = self.pattern.clone();
        let tag = self.tag.to_string();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: Some(handler),
            selected_handler: None,
            outcome: None,
            kind: crate::server::control::PendingKind::List {
                tag: tag.clone(),
                lsub: subscribed,
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let g = bundle.lock().unwrap();
                let store = g.store.as_ref().ok_or_else(|| "no store".to_string())?;
                let infos = if subscribed {
                    store
                        .list_subscribed(&reference, &pattern)
                        .map_err(|e| e.to_string())?
                } else {
                    store
                        .list(&reference, &pattern)
                        .map_err(|e| e.to_string())?
                };
                let delim = store.hierarchy_delimiter();
                let mut out = Vec::new();
                for info in infos {
                    let line = format!(
                        "{} \"{}\" {}",
                        format_list_attrs(&info.attributes),
                        delim,
                        quote_astring(&info.name)
                    );
                    out.extend_from_slice(line.as_bytes());
                    out.push(0);
                }
                Ok(out)
            },
            move |result: Result<Vec<u8>, StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        p.outcome = Some(result.map_err(|e| e.to_string()));
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn send_list(&mut self, infos: &[MailboxInfo], handler: Box<dyn AuthenticatedHandler>) {
        *self.authenticated = Some(handler);
        let delim = self
            .bundle
            .lock()
            .ok()
            .and_then(|g| g.store.as_ref().map(|s| s.hierarchy_delimiter()))
            .unwrap_or('/');
        for info in infos {
            let kind = if matches!(self.op, MgmtOp::Lsub) {
                "LSUB"
            } else {
                "LIST"
            };
            self.endpoint.send(&untagged(&format!(
                "{kind} {} \"{}\" {}",
                format_list_attrs(&info.attributes),
                delim,
                quote_astring(&info.name)
            )));
        }
        self.endpoint.send(&tagged_ok(self.tag, "LIST completed"));
    }

    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>) {
        *self.authenticated = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

pub(crate) struct AppendView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub mailbox: String,
    /// Path to the spooled literal (see `control::unique_append_spool_path`);
    /// streamed into the mailbox's append triad in bounded chunks rather
    /// than held whole in memory. Always `Some` for a valid APPEND, even a
    /// zero-length one (an empty spool file).
    pub body_path: Option<std::path::PathBuf>,
    #[allow(dead_code)]
    pub flags: BTreeSet<Flag>,
    #[allow(dead_code)]
    pub internal_date: Option<SystemTime>,
    pub authenticated: &'a mut Option<Box<dyn AuthenticatedHandler>>,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
}

impl AppendState for AppendView<'_> {
    fn proceed(
        &mut self,
        flags: BTreeSet<Flag>,
        internal_date: Option<SystemTime>,
        handler: Box<dyn AuthenticatedHandler>,
    ) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint.send(&tagged_no(self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let mailbox = self.mailbox.clone();
        let body_path = self.body_path.take();
        let tag = self.tag.to_string();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: Some(handler),
            selected_handler: None,
            outcome: None,
            kind: crate::server::control::PendingKind::Mgmt {
                tag: tag.clone(),
                ok: "APPEND completed".into(),
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let result = (|| -> Result<(u64, u64), String> {
                    let mut g = bundle.lock().unwrap();
                    // Append into selected mailbox if names match; else open target.
                    if g.mailbox.as_ref().map(|m| m.name()) == Some(mailbox.as_str()) {
                        let mb = g.mailbox.as_mut().unwrap();
                        let uid = append_streaming(
                            mb.as_mut(),
                            &flags,
                            internal_date,
                            body_path.as_deref(),
                        )
                        .map_err(|e| e.to_string())?;
                        let uv = mb.uid_validity();
                        Ok((uv, uid))
                    } else {
                        let store = g.store.as_mut().ok_or_else(|| "no store".to_string())?;
                        let mut mb = store
                            .open_mailbox(&mailbox, false)
                            .map_err(|e| e.to_string())?;
                        let uid = append_streaming(
                            mb.as_mut(),
                            &flags,
                            internal_date,
                            body_path.as_deref(),
                        )
                        .map_err(|e| e.to_string())?;
                        let uv = mb.uid_validity();
                        let _ = mb.close(false);
                        Ok((uv, uid))
                    }
                })();
                if let Some(path) = &body_path {
                    let _ = std::fs::remove_file(path);
                }
                let uid = result?;
                Ok(format!("[{}] APPEND completed", format_appenduid(uid.0, uid.1)).into_bytes())
            },
            move |result: Result<Vec<u8>, StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        match &result {
                            Ok(msg) => {
                                if let crate::server::control::PendingKind::Mgmt { ok, .. } =
                                    &mut p.kind
                                {
                                    *ok = String::from_utf8_lossy(msg).into_owned();
                                }
                                p.outcome = Some(Ok(Vec::new()));
                            }
                            Err(e) => p.outcome = Some(Err(e.to_string())),
                        }
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>) {
        if let Some(path) = self.body_path.take() {
            let _ = std::fs::remove_file(path);
        }
        *self.authenticated = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

/// Stream `body_path`'s content into the append triad in bounded chunks —
/// the message is never held whole in memory. `body_path` of `None` means a
/// zero-length message (append nothing between start/end). A mid-stream
/// failure rolls back via `AppendGuard` instead of leaving an orphaned
/// partial append.
fn append_streaming(
    mb: &mut dyn Mailbox,
    flags: &BTreeSet<Flag>,
    internal_date: Option<SystemTime>,
    body_path: Option<&std::path::Path>,
) -> hopf_mailbox::MailboxResult<u64> {
    use std::io::Read;
    let mut guard = hopf_mailbox::AppendGuard::start(mb, flags, internal_date)?;
    if let Some(path) = body_path {
        let mut f = std::fs::File::open(path)?;
        let mut buf = [0u8; 8192];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            guard.append_content(&buf[..n])?;
        }
    }
    guard.commit()
}

pub(crate) struct FetchView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub set: MessageSet,
    #[allow(dead_code)]
    pub by_uid: bool,
    pub changed_since: Option<u64>,
    pub selected: &'a mut Option<Box<dyn SelectedHandler>>,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
}

impl FetchState for FetchView<'_> {
    fn proceed(&mut self, items: Vec<FetchItem>, by_uid: bool, handler: Box<dyn SelectedHandler>) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint.send(&tagged_no(self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let set = self.set.clone();
        let changed_since = self.changed_since;
        let tag = self.tag.to_string();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        let set_seen = fetch_sets_seen(&items);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: None,
            selected_handler: Some(handler),
            outcome: None,
            kind: crate::server::control::PendingKind::Data {
                tag: tag.clone(),
                ok: "FETCH completed".into(),
            },
        });
        begin_busy(self.endpoint, self.busy);
        // Pushed straight to the wire as each message is formatted — see
        // `push_fetch_attrs` — instead of assembling every matched
        // message's response into one buffer first. `pending`'s own
        // `outcome` payload is always empty for FETCH: the untagged lines
        // have already gone out by the time it resolves, so the existing
        // `PendingKind::Data` completion path (shared with STORE) just
        // sends the tagged `OK` with nothing left to append.
        self.runtime.storage().submit_streamed(
            handle.clone(),
            move |conn| {
                let mut g = bundle.lock().unwrap();
                let read_only = g.read_only;
                let mb = g.mailbox.as_mut().ok_or_else(|| "no mailbox".to_string())?;
                let count = mb.message_count().map_err(|e| e.to_string())?;
                let last = count as u64;
                let mut buf = Vec::with_capacity(8192);
                for seq in 1..=count {
                    let uid = mb.uid(seq).map_err(|e| e.to_string())?;
                    let matched = if by_uid {
                        set.contains(uid, last.max(uid))
                    } else {
                        set.contains(seq as u64, last)
                    };
                    if !matched {
                        continue;
                    }
                    let modseq = mb.modseq(seq).unwrap_or(0);
                    if let Some(since) = changed_since {
                        // Only include messages the backend reports as changed.
                        // If modseq is unsupported (0), skip rather than lie.
                        if modseq == 0 || modseq <= since {
                            continue;
                        }
                    }
                    let flags = mb.flags(seq).map_err(|e| e.to_string())?;
                    let keywords = mb.keywords(seq).unwrap_or_default();
                    let size = mb
                        .messages()
                        .ok()
                        .and_then(|m| {
                            m.into_iter()
                                .find(|d| d.message_number == seq)
                                .map(|d| d.size)
                        })
                        .unwrap_or(0);
                    if set_seen && !read_only {
                        let mut seen = BTreeSet::new();
                        seen.insert(Flag::Seen);
                        let _ = mb.set_flags(seq, &seen, true);
                    }
                    let modseq_opt = if modseq > 0 { Some(modseq) } else { None };

                    buf.clear();
                    buf.extend_from_slice(format!("* {seq} FETCH ").as_bytes());
                    let push_result = push_fetch_attrs(
                        mb.as_mut(),
                        &items,
                        seq,
                        uid,
                        size,
                        &flags,
                        &keywords,
                        by_uid,
                        modseq_opt,
                        &mut |chunk: &[u8]| {
                            buf.extend_from_slice(chunk);
                            if buf.len() >= 8192 {
                                conn.send(std::mem::take(&mut buf));
                            }
                        },
                    );
                    buf.extend_from_slice(b"\r\n");
                    conn.send(std::mem::take(&mut buf));
                    push_result.map_err(|e| e.to_string())?;
                }
                Ok(())
            },
            move |result: Result<(), StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        p.outcome = Some(result.map(|_| Vec::new()).map_err(|e| e.to_string()));
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>) {
        *self.selected = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

pub(crate) struct StoreView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub set: MessageSet,
    #[allow(dead_code)]
    pub by_uid: bool,
    pub selected: &'a mut Option<Box<dyn SelectedHandler>>,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
}

impl StoreState for StoreView<'_> {
    fn proceed(
        &mut self,
        action: StoreAction,
        flags: BTreeSet<Flag>,
        keywords: BTreeSet<String>,
        silent: bool,
        by_uid: bool,
        handler: Box<dyn SelectedHandler>,
    ) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint.send(&tagged_no(self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let set = self.set.clone();
        let tag = self.tag.to_string();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: None,
            selected_handler: Some(handler),
            outcome: None,
            kind: crate::server::control::PendingKind::Data {
                tag: tag.clone(),
                ok: "STORE completed".into(),
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut g = bundle.lock().unwrap();
                if g.read_only {
                    return Err("mailbox is read-only".into());
                }
                let mb = g.mailbox.as_mut().ok_or_else(|| "no mailbox".to_string())?;
                let count = mb.message_count().map_err(|e| e.to_string())?;
                let last = count as u64;
                let mut out = Vec::new();
                for seq in 1..=count {
                    let uid = mb.uid(seq).map_err(|e| e.to_string())?;
                    let matched = if by_uid {
                        set.contains(uid, last.max(uid))
                    } else {
                        set.contains(seq as u64, last)
                    };
                    if !matched {
                        continue;
                    }
                    match action {
                        StoreAction::Add => {
                            mb.set_flags(seq, &flags, true).map_err(|e| e.to_string())?;
                            let _ = mb.set_keywords(seq, &keywords, true);
                        }
                        StoreAction::Remove => {
                            mb.set_flags(seq, &flags, false)
                                .map_err(|e| e.to_string())?;
                            let _ = mb.set_keywords(seq, &keywords, false);
                        }
                        StoreAction::Replace => {
                            mb.replace_flags(seq, &flags).map_err(|e| e.to_string())?;
                            let _ = mb.replace_keywords(seq, &keywords);
                        }
                    }
                    if !silent {
                        let f = mb.flags(seq).map_err(|e| e.to_string())?;
                        let k = mb.keywords(seq).unwrap_or_default();
                        let modseq = mb.modseq(seq).ok().filter(|&m| m > 0);
                        let attrs = format_fetch_attrs(
                            &[FetchItem::Flags],
                            seq,
                            uid,
                            0,
                            &f,
                            &k,
                            None,
                            by_uid,
                            modseq,
                        );
                        let mut line = format!("* {seq} FETCH ").into_bytes();
                        line.extend_from_slice(&attrs);
                        line.extend_from_slice(b"\r\n");
                        out.extend_from_slice(&line);
                    }
                }
                Ok(out)
            },
            move |result: Result<Vec<u8>, StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        p.outcome = Some(result.map_err(|e| e.to_string()));
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>) {
        *self.selected = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

pub(crate) struct SearchView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub criteria: SearchCriteria,
    #[allow(dead_code)]
    pub by_uid: bool,
    pub selected: &'a mut Option<Box<dyn SelectedHandler>>,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
}

impl SearchState for SearchView<'_> {
    fn proceed(&mut self, by_uid: bool, handler: Box<dyn SelectedHandler>) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint.send(&tagged_no(self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let criteria = self.criteria.clone();
        let tag = self.tag.to_string();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: None,
            selected_handler: Some(handler),
            outcome: None,
            kind: crate::server::control::PendingKind::Search {
                tag: tag.clone(),
                by_uid,
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let g = bundle.lock().unwrap();
                let mb = g.mailbox.as_ref().ok_or_else(|| "no mailbox".to_string())?;
                let seqs = mb.search(&criteria).map_err(|e| e.to_string())?;
                let mut nums = Vec::new();
                if by_uid {
                    for s in seqs {
                        let uid = mb.uid(s).map_err(|e| e.to_string())?;
                        nums.push(uid.to_string());
                    }
                } else {
                    for s in seqs {
                        nums.push(s.to_string());
                    }
                }
                Ok(nums.join(" ").into_bytes())
            },
            move |result: Result<Vec<u8>, StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        p.outcome = Some(result.map_err(|e| e.to_string()));
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>) {
        *self.selected = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

pub(crate) struct CopyView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub set: MessageSet,
    pub dest: String,
    #[allow(dead_code)]
    pub by_uid: bool,
    pub selected: &'a mut Option<Box<dyn SelectedHandler>>,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
}

impl CopyState for CopyView<'_> {
    fn proceed(&mut self, by_uid: bool, handler: Box<dyn SelectedHandler>) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint.send(&tagged_no(self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let set = self.set.clone();
        let dest = self.dest.clone();
        let tag = self.tag.to_string();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: None,
            selected_handler: Some(handler),
            outcome: None,
            kind: crate::server::control::PendingKind::Mgmt {
                tag: tag.clone(),
                ok: "COPY completed".into(),
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut g = bundle.lock().unwrap();
                let (src_uids, dest_uids) = {
                    let mb = g.mailbox.as_mut().ok_or_else(|| "no mailbox".to_string())?;
                    let count = mb.message_count().map_err(|e| e.to_string())?;
                    let last = count as u64;
                    let mut nums = Vec::new();
                    let mut src_uids = Vec::new();
                    for seq in 1..=count {
                        let uid = mb.uid(seq).map_err(|e| e.to_string())?;
                        let matched = if by_uid {
                            set.contains(uid, last.max(uid))
                        } else {
                            set.contains(seq as u64, last)
                        };
                        if matched {
                            nums.push(seq);
                            src_uids.push(uid);
                        }
                    }
                    let map = mb.copy_messages(&nums, &dest).map_err(|e| e.to_string())?;
                    let mut dest_uids = Vec::new();
                    for &n in &nums {
                        if let Some(&duid) = map.get(&n) {
                            dest_uids.push(duid);
                        }
                    }
                    (src_uids, dest_uids)
                };
                let uv = {
                    let store = g.store.as_mut().ok_or_else(|| "no store".to_string())?;
                    let target = store.open_mailbox(&dest, true).map_err(|e| e.to_string())?;
                    let uv = target.uid_validity();
                    let _ = target;
                    uv
                };
                let ok = if !src_uids.is_empty() && src_uids.len() == dest_uids.len() {
                    format!(
                        "[{}] COPY completed",
                        format_copyuid(uv, &src_uids, &dest_uids)
                    )
                } else {
                    "COPY completed".into()
                };
                Ok(ok.into_bytes())
            },
            move |result: Result<Vec<u8>, StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        match &result {
                            Ok(msg) => {
                                if let crate::server::control::PendingKind::Mgmt { ok, .. } =
                                    &mut p.kind
                                {
                                    *ok = String::from_utf8_lossy(msg).into_owned();
                                }
                                p.outcome = Some(Ok(Vec::new()));
                            }
                            Err(e) => p.outcome = Some(Err(e.to_string())),
                        }
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>) {
        *self.selected = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

/// Format `mailbox (MESSAGES n …)` for STATUS / LIST-STATUS (without `STATUS` verb).
pub(crate) fn format_status_line(
    name: &str,
    mb: &dyn Mailbox,
    items: &BTreeSet<StatusItem>,
) -> Result<String, String> {
    let status = mb.status().map_err(|e| e.to_string())?;
    let mut parts = Vec::new();
    for item in items {
        match item {
            StatusItem::Messages => parts.push(format!("MESSAGES {}", status.messages)),
            StatusItem::Recent => parts.push(format!("RECENT {}", status.recent)),
            StatusItem::UidNext => parts.push(format!("UIDNEXT {}", status.uid_next)),
            StatusItem::UidValidity => parts.push(format!("UIDVALIDITY {}", status.uid_validity)),
            StatusItem::Unseen => parts.push(format!("UNSEEN {}", status.unseen)),
            StatusItem::HighestModseq => {
                if status.highest_modseq > 0 {
                    parts.push(format!("HIGHESTMODSEQ {}", status.highest_modseq));
                }
            }
            StatusItem::Deleted => {
                let mut n = 0u32;
                let count = mb.message_count().map_err(|e| e.to_string())?;
                for seq in 1..=count {
                    if mb
                        .flags(seq)
                        .ok()
                        .map(|f| f.contains(&Flag::Deleted))
                        .unwrap_or(false)
                    {
                        n += 1;
                    }
                }
                parts.push(format!("DELETED {n}"));
            }
            StatusItem::Size => {
                let size = mb.mailbox_size().unwrap_or(0);
                parts.push(format!("SIZE {size}"));
            }
        }
    }
    Ok(format!("{} ({})", quote_astring(name), parts.join(" ")))
}

pub(crate) struct StatusView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub name: String,
    #[allow(dead_code)]
    pub items: BTreeSet<StatusItem>,
    #[allow(dead_code)]
    pub authenticated: &'a mut Option<Box<dyn AuthenticatedHandler>>,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
}

impl StatusState for StatusView<'_> {
    fn proceed(&mut self, items: BTreeSet<StatusItem>, handler: Box<dyn AuthenticatedHandler>) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint.send(&tagged_no(self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let name = self.name.clone();
        let tag = self.tag.to_string();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: Some(handler),
            selected_handler: None,
            outcome: None,
            kind: crate::server::control::PendingKind::Data {
                tag: tag.clone(),
                ok: "STATUS completed".into(),
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut g = bundle.lock().unwrap();
                // Prefer selected mailbox if names match.
                let line = if g.mailbox.as_ref().map(|m| m.name()) == Some(name.as_str()) {
                    let mb = g.mailbox.as_ref().unwrap();
                    format_status_line(&name, mb.as_ref(), &items)?
                } else {
                    let store = g.store.as_mut().ok_or_else(|| "no store".to_string())?;
                    let mb = store.open_mailbox(&name, true).map_err(|e| e.to_string())?;
                    let line = format_status_line(&name, mb.as_ref(), &items)?;
                    let _ = mb;
                    line
                };
                let out = untagged(&format!("STATUS {line}"));
                Ok(out)
            },
            move |result: Result<Vec<u8>, StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        p.outcome = Some(result.map_err(|e| e.to_string()));
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn no(&mut self, message: &str, handler: Box<dyn AuthenticatedHandler>) {
        *self.authenticated = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

pub(crate) struct MoveView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub set: MessageSet,
    pub dest: String,
    #[allow(dead_code)]
    pub by_uid: bool,
    pub qresync: bool,
    pub selected: &'a mut Option<Box<dyn SelectedHandler>>,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
}

impl MoveState for MoveView<'_> {
    fn proceed(&mut self, by_uid: bool, handler: Box<dyn SelectedHandler>) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint.send(&tagged_no(self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let set = self.set.clone();
        let dest = self.dest.clone();
        let qresync = self.qresync;
        let tag = self.tag.to_string();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: None,
            selected_handler: Some(handler),
            outcome: None,
            kind: crate::server::control::PendingKind::Data {
                tag: tag.clone(),
                ok: "MOVE completed".into(),
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut g = bundle.lock().unwrap();
                if g.read_only {
                    return Err("mailbox is read-only".into());
                }
                let map = {
                    if g.read_only {
                        return Err("mailbox is read-only".into());
                    }
                    let mb = g.mailbox.as_mut().ok_or_else(|| "no mailbox".to_string())?;
                    let count = mb.message_count().map_err(|e| e.to_string())?;
                    let last = count as u64;
                    let mut nums = Vec::new();
                    let mut src_uids = Vec::new();
                    for seq in 1..=count {
                        let uid = mb.uid(seq).map_err(|e| e.to_string())?;
                        let matched = if by_uid {
                            set.contains(uid, last.max(uid))
                        } else {
                            set.contains(seq as u64, last)
                        };
                        if matched {
                            nums.push(seq);
                            src_uids.push(uid);
                        }
                    }
                    let map = mb.move_messages(&nums, &dest).map_err(|e| e.to_string())?;
                    (nums, src_uids, map)
                };
                let (nums, src_uids, map) = map;
                let mut dest_uids = Vec::new();
                for &n in &nums {
                    if let Some(&duid) = map.get(&n) {
                        dest_uids.push(duid);
                    }
                }
                let uv = {
                    let store = g.store.as_mut().ok_or_else(|| "no store".to_string())?;
                    let target = store.open_mailbox(&dest, true).map_err(|e| e.to_string())?;
                    let uv = target.uid_validity();
                    let _ = target;
                    uv
                };
                let expunged = {
                    let mb = g.mailbox.as_mut().ok_or_else(|| "no mailbox".to_string())?;
                    mb.expunge().map_err(|e| e.to_string())?
                };
                let mut out = Vec::new();
                if qresync && !src_uids.is_empty() {
                    let vanished = src_uids
                        .iter()
                        .map(|u| u.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    out.extend_from_slice(&untagged(&format!("VANISHED {vanished}")));
                } else {
                    // EXPUNGE in descending sequence order.
                    let mut seqs = expunged;
                    seqs.sort_unstable();
                    for seq in seqs.into_iter().rev() {
                        out.extend_from_slice(&untagged(&format!("{seq} EXPUNGE")));
                    }
                }
                let ok = if !src_uids.is_empty() && src_uids.len() == dest_uids.len() {
                    format!(
                        "[{}] MOVE completed",
                        format_copyuid(uv, &src_uids, &dest_uids)
                    )
                } else {
                    "MOVE completed".into()
                };
                // Encode OK into pending via trailing NUL + ok text after payload.
                out.push(0);
                out.extend_from_slice(ok.as_bytes());
                Ok(out)
            },
            move |result: Result<Vec<u8>, StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        match result {
                            Ok(mut raw) => {
                                if let Some(pos) = raw.iter().rposition(|&b| b == 0) {
                                    let ok = String::from_utf8_lossy(&raw[pos + 1..]).into_owned();
                                    raw.truncate(pos);
                                    if let crate::server::control::PendingKind::Data {
                                        ok: ok_slot,
                                        ..
                                    } = &mut p.kind
                                    {
                                        *ok_slot = ok;
                                    }
                                    p.outcome = Some(Ok(raw));
                                } else {
                                    p.outcome = Some(Ok(raw));
                                }
                            }
                            Err(e) => p.outcome = Some(Err(e.to_string())),
                        }
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>) {
        *self.selected = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}

pub(crate) struct ExpungeView<'a> {
    pub endpoint: &'a mut dyn Endpoint,
    pub tag: &'a str,
    pub uid_set: Option<MessageSet>,
    pub qresync: bool,
    pub selected: &'a mut Option<Box<dyn SelectedHandler>>,
    pub bundle: &'a Arc<Mutex<MailboxBundle>>,
    pub runtime: &'a Arc<Runtime>,
    pub busy: &'a Arc<AtomicBool>,
    pub control_handle: &'a Option<ConnHandle>,
    pub pending_open: &'a Arc<Mutex<Option<PendingOpen>>>,
}

impl ExpungeState for ExpungeView<'_> {
    fn proceed(&mut self, handler: Box<dyn SelectedHandler>) {
        let Some(handle) = self.control_handle.clone() else {
            self.endpoint.send(&tagged_no(self.tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(self.bundle);
        let uid_set = self.uid_set.clone();
        let qresync = self.qresync;
        let tag = self.tag.to_string();
        let busy = Arc::clone(self.busy);
        let pending = Arc::clone(self.pending_open);
        let ok = if uid_set.is_some() {
            "UID EXPUNGE completed"
        } else {
            "EXPUNGE completed"
        };
        *pending.lock().unwrap() = Some(PendingOpen {
            auth_handler: None,
            selected_handler: Some(handler),
            outcome: None,
            kind: crate::server::control::PendingKind::Data {
                tag: tag.clone(),
                ok: ok.into(),
            },
        });
        begin_busy(self.endpoint, self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut g = bundle.lock().unwrap();
                if g.read_only {
                    return Err("mailbox is read-only".into());
                }
                let mb = g.mailbox.as_mut().ok_or_else(|| "no mailbox".to_string())?;
                if let Some(ref set) = uid_set {
                    // UID EXPUNGE: temporarily clear \Deleted on UIDs outside the set.
                    let count = mb.message_count().map_err(|e| e.to_string())?;
                    let last = count as u64;
                    let mut protected = Vec::new();
                    let mut del = BTreeSet::new();
                    del.insert(Flag::Deleted);
                    for seq in 1..=count {
                        let uid = mb.uid(seq).map_err(|e| e.to_string())?;
                        let flags = mb.flags(seq).map_err(|e| e.to_string())?;
                        if flags.contains(&Flag::Deleted) && !set.contains(uid, last.max(uid)) {
                            mb.set_flags(seq, &del, false).map_err(|e| e.to_string())?;
                            protected.push(uid);
                        }
                    }
                    let expunged_uids: Vec<u64> = {
                        let count = mb.message_count().map_err(|e| e.to_string())?;
                        let mut u = Vec::new();
                        for seq in 1..=count {
                            let flags = mb.flags(seq).map_err(|e| e.to_string())?;
                            if flags.contains(&Flag::Deleted) {
                                u.push(mb.uid(seq).map_err(|e| e.to_string())?);
                            }
                        }
                        u
                    };
                    let seqs = mb.expunge().map_err(|e| e.to_string())?;
                    // Restore \Deleted on protected UIDs that remain.
                    let count = mb.message_count().map_err(|e| e.to_string())?;
                    for seq in 1..=count {
                        let uid = mb.uid(seq).map_err(|e| e.to_string())?;
                        if protected.contains(&uid) {
                            let _ = mb.set_flags(seq, &del, true);
                        }
                    }
                    let mut out = Vec::new();
                    if qresync && !expunged_uids.is_empty() {
                        let vanished = expunged_uids
                            .iter()
                            .map(|u| u.to_string())
                            .collect::<Vec<_>>()
                            .join(",");
                        out.extend_from_slice(&untagged(&format!("VANISHED {vanished}")));
                    } else {
                        let mut seqs = seqs;
                        seqs.sort_unstable();
                        for seq in seqs.into_iter().rev() {
                            out.extend_from_slice(&untagged(&format!("{seq} EXPUNGE")));
                        }
                    }
                    Ok(out)
                } else {
                    let expunged_uids: Vec<u64> = if qresync {
                        let count = mb.message_count().map_err(|e| e.to_string())?;
                        let mut u = Vec::new();
                        for seq in 1..=count {
                            let flags = mb.flags(seq).map_err(|e| e.to_string())?;
                            if flags.contains(&Flag::Deleted) {
                                u.push(mb.uid(seq).map_err(|e| e.to_string())?);
                            }
                        }
                        u
                    } else {
                        Vec::new()
                    };
                    let seqs = mb.expunge().map_err(|e| e.to_string())?;
                    let mut out = Vec::new();
                    if qresync && !expunged_uids.is_empty() {
                        let vanished = expunged_uids
                            .iter()
                            .map(|u| u.to_string())
                            .collect::<Vec<_>>()
                            .join(",");
                        out.extend_from_slice(&untagged(&format!("VANISHED {vanished}")));
                    } else {
                        let mut seqs = seqs;
                        seqs.sort_unstable();
                        for seq in seqs.into_iter().rev() {
                            out.extend_from_slice(&untagged(&format!("{seq} EXPUNGE")));
                        }
                    }
                    Ok(out)
                }
            },
            move |result: Result<Vec<u8>, StorageError>| {
                handle.with_endpoint(move |ep| {
                    if let Some(p) = pending.lock().unwrap().as_mut() {
                        p.outcome = Some(result.map_err(|e| e.to_string()));
                    }
                    end_busy(ep, &busy);
                });
            },
        );
    }

    fn no(&mut self, message: &str, handler: Box<dyn SelectedHandler>) {
        *self.selected = Some(handler);
        self.endpoint.send(&tagged_no(self.tag, message));
    }
}
