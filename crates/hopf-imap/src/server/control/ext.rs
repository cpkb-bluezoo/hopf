// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Extension command handlers (IDLE, ENABLE, NAMESPACE, STATUS, QUOTA, MOVE, …).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use hopf_core::{Endpoint, StorageError, TimerHandle};
use hopf_mailbox::{MailboxAttribute, MessageSet};

use super::ImapControlHandler;
use crate::enable::parse_enable_args;
use crate::server::codec::{parse_astring, parse_sequence_set, ImapCommand};
use crate::server::idle::{idle_update_lines, IdleMailboxSnapshot, IDLE_POLL_INTERVAL};
use crate::server::list_ext::ListCommand;
use crate::server::quota::parse_quota_resource_list;
use crate::server::reply::{
    continuation, format_list_attrs, quote_astring, tagged_bad, tagged_no, tagged_ok, untagged,
};
use crate::server::session::ImapSessionState;
use crate::server::status_items::parse_status_command;
use crate::server::views::{
    begin_busy, end_busy, format_status_line, ExpungeView, MoveView, StatusView,
};

impl ImapControlHandler {
    pub(super) fn cmd_noop(&mut self, endpoint: &mut dyn Endpoint, tag: &str) {
        if self.session == ImapSessionState::Selected {
            let snap = self.bundle.lock().ok().and_then(|g| {
                g.mailbox.as_ref().and_then(|mb| {
                    let status = mb.status().ok()?;
                    Some(IdleMailboxSnapshot {
                        exists: status.messages,
                        recent: status.recent,
                    })
                })
            });
            if let Some(snap) = snap {
                for line in idle_update_lines(&self.idle, &snap) {
                    self.send(endpoint, untagged(&line));
                }
                self.idle.last_exists = snap.exists;
                self.idle.last_recent = snap.recent;
                *self.idle.shared.counts.lock().unwrap() = (snap.exists, snap.recent);
            }
        }
        self.send(endpoint, tagged_ok(tag, "NOOP completed"));
    }

    pub(super) fn cmd_id(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        let _ = cmd.args;
        let mut fields = self.config.server_id.clone();
        if fields.is_empty() {
            fields.insert("name".into(), "hopf-imap".into());
            fields.insert("version".into(), env!("CARGO_PKG_VERSION").into());
        }
        let mut parts = Vec::new();
        for (k, v) in &fields {
            parts.push(format!("\"{k}\" \"{v}\""));
        }
        self.send(endpoint, untagged(&format!("ID ({})", parts.join(" "))));
        self.send(endpoint, tagged_ok(&cmd.tag, "ID completed"));
    }

    pub(super) fn cmd_enable(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if !self.require_auth(endpoint, &cmd.tag) {
            return;
        }
        if !self.config.enable_enable {
            self.send(endpoint, tagged_bad(&cmd.tag, "ENABLE not available"));
            return;
        }
        let tokens = parse_enable_args(&cmd.args);
        let refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
        let newly = self.enabled.enable(
            &refs,
            self.config.enable_condstore,
            self.config.enable_qresync,
        );
        if !newly.is_empty() {
            self.send(endpoint, untagged(&format!("ENABLED {}", newly.join(" "))));
        }
        self.send(endpoint, tagged_ok(&cmd.tag, "ENABLE completed"));
    }

    pub(super) fn cmd_namespace(&mut self, endpoint: &mut dyn Endpoint, tag: &str) {
        if !self.require_auth(endpoint, tag) {
            return;
        }
        if !self.config.enable_namespace {
            self.send(endpoint, tagged_bad(tag, "NAMESPACE not available"));
            return;
        }
        let (personal, delim) = self
            .bundle
            .lock()
            .ok()
            .and_then(|g| {
                g.store
                    .as_ref()
                    .map(|s| (s.personal_namespace().to_string(), s.hierarchy_delimiter()))
            })
            .unwrap_or_else(|| (String::new(), '/'));
        let personal_ns = format!("((\"{personal}\" \"{delim}\"))");
        self.send(
            endpoint,
            untagged(&format!("NAMESPACE {personal_ns} NIL NIL")),
        );
        self.send(endpoint, tagged_ok(tag, "NAMESPACE completed"));
    }

    pub(super) fn cmd_idle(&mut self, endpoint: &mut dyn Endpoint, tag: &str) {
        if !self.require_selected(endpoint, tag) {
            return;
        }
        if !self.config.enable_idle {
            self.send(endpoint, tagged_bad(tag, "IDLE not available"));
            return;
        }
        let (exists, recent) = self
            .bundle
            .lock()
            .ok()
            .and_then(|g| {
                g.mailbox.as_ref().and_then(|mb| {
                    let st = mb.status().ok()?;
                    Some((st.messages, st.recent))
                })
            })
            .unwrap_or((0, 0));
        self.idle.begin(tag.to_string(), exists, recent);
        self.send(endpoint, continuation("idling"));
        self.arm_idle_timer(endpoint);
    }

    pub(super) fn cmd_idle_done(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(tag) = self.idle.end() {
            self.idle.sync_from_shared();
            self.send(endpoint, tagged_ok(&tag, "IDLE completed"));
        }
    }

    fn arm_idle_timer(&mut self, endpoint: &mut dyn Endpoint) {
        let handle = endpoint.handle();
        let bundle = Arc::clone(&self.bundle);
        let shared = self.idle.shared.clone();
        let runtime = Arc::clone(&self.runtime);

        fn schedule(
            endpoint: &mut dyn Endpoint,
            handle: hopf_core::ConnHandle,
            bundle: Arc<std::sync::Mutex<super::MailboxBundle>>,
            shared: crate::server::idle::IdleShared,
            runtime: Arc<hopf_core::Runtime>,
        ) {
            if !shared.is_active() {
                return;
            }
            let handle_cb = handle.clone();
            let bundle_cb = Arc::clone(&bundle);
            let shared_cb = shared.clone();
            let runtime_cb = Arc::clone(&runtime);
            let timer: TimerHandle = endpoint.schedule_timer(
                IDLE_POLL_INTERVAL,
                Box::new(move || {
                    if !shared_cb.is_active() {
                        return;
                    }
                    let handle2 = handle_cb.clone();
                    let shared2 = shared_cb.clone();
                    let bundle2 = Arc::clone(&bundle_cb);
                    let runtime2 = Arc::clone(&runtime_cb);
                    runtime_cb.storage().submit_on(
                        handle_cb.clone(),
                        move || {
                            let g = bundle_cb.lock().map_err(|e| e.to_string())?;
                            let mb = g.mailbox.as_ref().ok_or_else(|| "no mailbox".to_string())?;
                            let st = mb.status().map_err(|e| e.to_string())?;
                            Ok((st.messages, st.recent))
                        },
                        move |result: Result<(u32, u32), StorageError>| {
                            let handle3 = handle2.clone();
                            handle2.with_endpoint(move |ep| {
                                if !shared2.is_active() {
                                    return;
                                }
                                if let Ok((exists, recent)) = result {
                                    let mut counts = shared2.counts.lock().unwrap();
                                    if exists != counts.0 {
                                        ep.send(&untagged(&format!("{exists} EXISTS")));
                                        counts.0 = exists;
                                    }
                                    if recent != counts.1 {
                                        ep.send(&untagged(&format!("{recent} RECENT")));
                                        counts.1 = recent;
                                    }
                                }
                                schedule(ep, handle3, bundle2, shared2, runtime2);
                            });
                        },
                    );
                }),
            );
            *shared.timer.lock().unwrap() = Some(timer);
        }

        schedule(endpoint, handle, bundle, shared, runtime);
    }

    pub(super) fn cmd_status(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if !self.require_auth(endpoint, &cmd.tag) {
            return;
        }
        let (name, items) = match parse_status_command(&cmd.args) {
            Ok(v) => v,
            Err(e) => {
                self.send(endpoint, tagged_bad(&cmd.tag, &e));
                return;
            }
        };
        if let Some(mut h) = self.selected.take() {
            let mut view = StatusView {
                endpoint,
                tag: &cmd.tag,
                name: name.clone(),
                items: items.clone(),
                authenticated: &mut self.authenticated,
                bundle: &self.bundle,
                runtime: &self.runtime,
                busy: &self.busy,
                control_handle: &self.control_handle,
                pending_open: &self.pending_open,
            };
            let g = self.bundle.lock().unwrap();
            if let Some(store) = g.store.as_ref() {
                h.status(&mut view, store.as_ref(), &name, &items);
            }
            drop(g);
            if self.selected.is_none() && self.pending_open.lock().unwrap().is_none() {
                self.selected = Some(h);
            }
            return;
        }
        if let Some(mut h) = self.authenticated.take() {
            let mut view = StatusView {
                endpoint,
                tag: &cmd.tag,
                name: name.clone(),
                items: items.clone(),
                authenticated: &mut self.authenticated,
                bundle: &self.bundle,
                runtime: &self.runtime,
                busy: &self.busy,
                control_handle: &self.control_handle,
                pending_open: &self.pending_open,
            };
            let g = self.bundle.lock().unwrap();
            if let Some(store) = g.store.as_ref() {
                h.status(&mut view, store.as_ref(), &name, &items);
            }
            drop(g);
            if self.authenticated.is_none() && self.pending_open.lock().unwrap().is_none() {
                self.authenticated = Some(h);
            }
        }
    }

    pub(super) fn run_list_ext(
        &mut self,
        endpoint: &mut dyn Endpoint,
        tag: &str,
        parsed: ListCommand,
        subscribed: bool,
    ) {
        let Some(handle) = self.control_handle.clone() else {
            self.send(endpoint, tagged_no(tag, "Internal error"));
            return;
        };
        let bundle = Arc::clone(&self.bundle);
        let reference = parsed.reference.clone();
        let pattern = parsed.pattern.clone();
        let ret = parsed.ret.clone();
        let tag_owned = tag.to_string();
        let busy = Arc::clone(&self.busy);
        let pending = Arc::clone(&self.pending_open);
        *pending.lock().unwrap() = Some(super::PendingOpen {
            auth_handler: self.authenticated.take(),
            selected_handler: self.selected.take(),
            outcome: None,
            kind: super::PendingKind::List {
                tag: tag_owned,
                lsub: false,
            },
        });
        begin_busy(endpoint, &self.busy);
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let infos = {
                    let g = bundle.lock().unwrap();
                    let store = g.store.as_ref().ok_or_else(|| "no store".to_string())?;
                    if subscribed {
                        store
                            .list_subscribed(&reference, &pattern)
                            .map_err(|e| e.to_string())?
                    } else {
                        store
                            .list(&reference, &pattern)
                            .map_err(|e| e.to_string())?
                    }
                };
                let delim = {
                    let g = bundle.lock().unwrap();
                    g.store
                        .as_ref()
                        .map(|s| s.hierarchy_delimiter())
                        .unwrap_or('/')
                };
                let mut out = Vec::new();
                let names: Vec<(String, _)> = infos
                    .into_iter()
                    .map(|i| (i.name.clone(), i.attributes))
                    .collect();
                for (name, mut attrs) in names {
                    if ret.children
                        && !attrs.contains(&MailboxAttribute::HasChildren)
                        && !attrs.contains(&MailboxAttribute::HasNoChildren)
                    {
                        attrs.insert(MailboxAttribute::HasNoChildren);
                    }
                    let line = format!(
                        "{} \"{}\" {}",
                        format_list_attrs(&attrs),
                        delim,
                        quote_astring(&name)
                    );
                    out.extend_from_slice(line.as_bytes());
                    out.push(0);
                    if !ret.status.is_empty() {
                        let mut g = bundle.lock().unwrap();
                        let store = g.store.as_mut().ok_or_else(|| "no store".to_string())?;
                        if let Ok(mut mb) = store.open_mailbox(&name, true) {
                            let status_line = format_status_line(&name, mb.as_ref(), &ret.status)?;
                            out.extend_from_slice(b"STATUS ");
                            out.extend_from_slice(status_line.as_bytes());
                            out.push(0);
                            let _ = mb.close(false);
                        }
                    }
                }
                let _ = subscribed;
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

    pub(super) fn cmd_getquota(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if !self.require_auth(endpoint, &cmd.tag) {
            return;
        }
        if !self.config.enable_quota {
            self.send(endpoint, tagged_bad(&cmd.tag, "QUOTA not available"));
            return;
        }
        let root = cmd.args.trim().trim_matches('"').to_string();
        let username = self.username.clone().unwrap_or_default();
        let q = self.config.quota_manager.get_quota(&username);
        self.send(endpoint, untagged(&q.format_response(&root)));
        self.send(endpoint, tagged_ok(&cmd.tag, "GETQUOTA completed"));
    }

    pub(super) fn cmd_getquotaroot(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if !self.require_auth(endpoint, &cmd.tag) {
            return;
        }
        if !self.config.enable_quota {
            self.send(endpoint, tagged_bad(&cmd.tag, "QUOTA not available"));
            return;
        }
        let Ok((mailbox, _)) = parse_astring(cmd.args.trim()) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid mailbox"));
            return;
        };
        let username = self.username.clone().unwrap_or_default();
        let root = "";
        self.send(
            endpoint,
            untagged(&format!(
                "QUOTAROOT {} {}",
                quote_astring(&mailbox),
                quote_astring(root)
            )),
        );
        let q = self.config.quota_manager.get_quota(&username);
        self.send(endpoint, untagged(&q.format_response(root)));
        self.send(endpoint, tagged_ok(&cmd.tag, "GETQUOTAROOT completed"));
    }

    pub(super) fn cmd_setquota(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand) {
        if !self.require_auth(endpoint, &cmd.tag) {
            return;
        }
        if !self.config.enable_quota {
            self.send(endpoint, tagged_bad(&cmd.tag, "QUOTA not available"));
            return;
        }
        let Ok((root, rest)) = parse_astring(cmd.args.trim()) else {
            self.send(endpoint, tagged_bad(&cmd.tag, "Invalid quota root"));
            return;
        };
        let resources = match parse_quota_resource_list(rest) {
            Ok(r) => r,
            Err(e) => {
                self.send(endpoint, tagged_bad(&cmd.tag, &e));
                return;
            }
        };
        let username = self.username.clone().unwrap_or_default();
        match self.config.quota_manager.set_quota(&username, resources) {
            Ok(q) => {
                self.send(endpoint, untagged(&q.format_response(&root)));
                self.send(endpoint, tagged_ok(&cmd.tag, "SETQUOTA completed"));
            }
            Err(e) => self.send(endpoint, tagged_no(&cmd.tag, &e)),
        }
    }

    pub(super) fn cmd_move(&mut self, endpoint: &mut dyn Endpoint, cmd: ImapCommand, by_uid: bool) {
        if !self.require_selected(endpoint, &cmd.tag) {
            return;
        }
        if !self.config.enable_move {
            self.send(endpoint, tagged_bad(&cmd.tag, "MOVE not available"));
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
        let mut view = MoveView {
            endpoint,
            tag: &cmd.tag,
            set: set.clone(),
            dest: dest.clone(),
            by_uid,
            qresync: self.enabled.qresync,
            selected: &mut self.selected,
            bundle: &self.bundle,
            runtime: &self.runtime,
            busy: &self.busy,
            control_handle: &self.control_handle,
            pending_open: &self.pending_open,
        };
        let g = self.bundle.lock().unwrap();
        if let Some(mb) = g.mailbox.as_ref() {
            h.move_messages(&mut view, mb.as_ref(), &set, &dest, by_uid);
        }
        drop(g);
        if self.selected.is_none() && self.pending_open.lock().unwrap().is_none() {
            self.selected = Some(h);
        }
    }

    pub(super) fn cmd_expunge(
        &mut self,
        endpoint: &mut dyn Endpoint,
        tag: &str,
        uid_set: Option<MessageSet>,
    ) {
        if !self.require_selected(endpoint, tag) {
            return;
        }
        let Some(mut h) = self.selected.take() else {
            return;
        };
        let mut view = ExpungeView {
            endpoint,
            tag,
            uid_set: uid_set.clone(),
            qresync: self.enabled.qresync,
            selected: &mut self.selected,
            bundle: &self.bundle,
            runtime: &self.runtime,
            busy: &self.busy,
            control_handle: &self.control_handle,
            pending_open: &self.pending_open,
        };
        let g = self.bundle.lock().unwrap();
        if let Some(mb) = g.mailbox.as_ref() {
            if let Some(ref set) = uid_set {
                h.uid_expunge(&mut view, mb.as_ref(), set);
            } else {
                h.expunge(&mut view, mb.as_ref());
            }
        }
        drop(g);
        if self.selected.is_none() && self.pending_open.lock().unwrap().is_none() {
            self.selected = Some(h);
        }
        let _ = Ordering::Relaxed;
    }
}
