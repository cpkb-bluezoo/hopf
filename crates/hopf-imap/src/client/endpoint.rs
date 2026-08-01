// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `ImapClientEndpoint` — async IMAP client as a [`ProtocolHandler`].
//!
//! Correlates pipelined tagged replies via [`PendingMap`], routes untagged
//! responses (now already-typed [`ImapEvent`] variants, not raw text) to
//! the oldest compatible pending command, and delivers unsolicited EXISTS /
//! EXPUNGE / FLAGS to [`MailboxEventListener`] (including during active
//! IDLE).

use std::io;
use std::time::Duration;

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, SharedTlsConnector, TimerHandle};
use rmimeparser::charset::base64;

use super::handlers::{ImapClientDriver, ImapClientHandlerFactory};
use super::pending::{ImapTagGenerator, PendingCommand, PendingKind, PendingMap, UntaggedClass};
use super::reply::{ImapEvent, ImapReplyLexer, ImapStatus};
use super::state::{
    ImapAppendUid, ImapCapabilities, ImapClientAppend, ImapClientAuthExchange,
    ImapClientAuthenticated, ImapClientIdle, ImapClientNotAuthenticated, ImapClientPostStarttls,
    ImapClientSelected, ImapCopyUid, ImapEnabledFeatures, ImapFetchData, ImapListEntry,
    ImapMailboxInfo, ImapNamespaceData, ImapQuotaData, ImapQuotaRootData, ImapStatusData,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    Connecting,
    NotAuthenticated,
    PendingTls,
    Authenticated,
    Selected,
    /// IDLE issued; waiting for `+`.
    IdleSent,
    /// IDLE active; mailbox events until `DONE` + tagged OK.
    IdleActive,
    Logout,
    Error,
    Closed,
}

/// Async IMAP client [`ProtocolHandler`].
pub struct ImapClientEndpoint {
    driver: Option<Box<dyn ImapClientDriver>>,
    session: SessionState,
    caps: ImapCapabilities,
    enabled: ImapEnabledFeatures,
    lexer: ImapReplyLexer,
    tags: ImapTagGenerator,
    pending: PendingMap,
    tls_connector: Option<SharedTlsConnector>,
    tls_server_name: Option<String>,
    implicit_tls_pending: bool,
    stage_timeout: Duration,
    message_timeout: Duration,
    connect_timeout: Duration,
    greeting_timer: Option<TimerHandle>,
    message_timer: Option<TimerHandle>,
    outbound: Vec<u8>,
    /// SELECT / EXAMINE accumulator.
    select_info: ImapMailboxInfo,
    /// Untagged `CAPABILITY` seen mid-command, consumed at tagged completion.
    capa_buf: Option<ImapCapabilities>,
    /// APPEND payload waiting for `+` (when not using LITERAL-).
    append_pending_data: Option<Vec<u8>>,
    /// When true, next APPEND data is flushed immediately after command (LITERAL-).
    append_literal_minus: bool,
    /// Last `issue_no_ep` failure (surfaced on next flush).
    pending_issue_error: Option<String>,
    /// Last COPYUID seen for MOVE/COPY completion.
    last_copyuid: Option<ImapCopyUid>,
    /// Last APPENDUID seen for APPEND completion.
    last_appenduid: Option<ImapAppendUid>,
    /// Selected before IDLE (restored on DONE completion).
    was_selected: bool,
}

impl ImapClientEndpoint {
    /// Create a new endpoint from a factory.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        factory: &dyn ImapClientHandlerFactory,
        stage_timeout: Duration,
        message_timeout: Duration,
        connect_timeout: Duration,
        tls_connector: Option<SharedTlsConnector>,
        tls_server_name: Option<String>,
        implicit_tls: bool,
        max_pipeline: usize,
    ) -> Self {
        Self {
            driver: Some(factory.create()),
            session: SessionState::Connecting,
            caps: ImapCapabilities::default(),
            enabled: ImapEnabledFeatures::default(),
            lexer: ImapReplyLexer::new(),
            tags: ImapTagGenerator::new(),
            pending: PendingMap::new(max_pipeline),
            tls_connector,
            tls_server_name,
            implicit_tls_pending: implicit_tls,
            stage_timeout,
            message_timeout,
            connect_timeout,
            greeting_timer: None,
            message_timer: None,
            outbound: Vec::with_capacity(512),
            select_info: ImapMailboxInfo::default(),
            capa_buf: None,
            append_pending_data: None,
            append_literal_minus: false,
            pending_issue_error: None,
            last_copyuid: None,
            last_appenduid: None,
            was_selected: false,
        }
    }

    /// Outstanding pending commands (for tests / pipelining demos).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Whether IDLE is active (after `+`, before tagged DONE completion).
    pub fn is_idle_active(&self) -> bool {
        self.session == SessionState::IdleActive
    }

    fn write_raw(&mut self, bytes: &[u8]) {
        self.outbound.extend_from_slice(bytes);
    }

    fn write_line(&mut self, line: &str) {
        self.write_raw(line.as_bytes());
        self.write_raw(b"\r\n");
    }

    fn flush_outbound(&mut self, ep: &mut dyn Endpoint) {
        if let Some(msg) = self.pending_issue_error.take() {
            self.protocol_error(ep, msg);
            return;
        }
        self.ensure_pending_timers(ep);
        if !self.outbound.is_empty() {
            let out = std::mem::take(&mut self.outbound);
            ep.send(&out);
        }
    }

    fn ensure_pending_timers(&mut self, ep: &mut dyn Endpoint) {
        if self.stage_timeout.is_zero() {
            return;
        }
        // While IDLE is active, do not arm a stage timer on the Idle pending
        // command (DONE is client-driven). IdleSent still times out waiting for `+`.
        let idle_active = self.session == SessionState::IdleActive;
        let timeout = self.stage_timeout;
        self.pending.arm_missing_timers(|kind| {
            if idle_active && kind == PendingKind::Idle {
                return None;
            }
            let handle = ep.handle();
            Some(ep.schedule_timer(
                timeout,
                Box::new(move || {
                    handle.with_endpoint(|ep2| {
                        ep2.fail(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "IMAP command timed out",
                        ));
                    });
                }),
            ))
        });
    }

    fn cancel_greeting_timer(&mut self) {
        if let Some(t) = self.greeting_timer.take() {
            t.cancel();
        }
    }

    fn cancel_message_timer(&mut self) {
        if let Some(t) = self.message_timer.take() {
            t.cancel();
        }
    }

    fn arm_greeting_timer(&mut self, ep: &mut dyn Endpoint) {
        self.cancel_greeting_timer();
        if self.connect_timeout.is_zero() {
            return;
        }
        let handle = ep.handle();
        let timer = ep.schedule_timer(
            self.connect_timeout,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "IMAP greeting timed out",
                    ));
                });
            }),
        );
        self.greeting_timer = Some(timer);
    }

    fn arm_message_timer(&mut self, ep: &mut dyn Endpoint) {
        self.cancel_message_timer();
        if self.message_timeout.is_zero() {
            return;
        }
        let handle = ep.handle();
        let timer = ep.schedule_timer(
            self.message_timeout,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "IMAP message transfer timed out",
                    ));
                });
            }),
        );
        self.message_timer = Some(timer);
    }

    fn protocol_error(&mut self, ep: &mut dyn Endpoint, msg: impl Into<String>) {
        self.session = SessionState::Error;
        let err = io::Error::new(io::ErrorKind::InvalidData, msg.into());
        self.pending.drain_all();
        self.cancel_greeting_timer();
        self.cancel_message_timer();
        if let Some(mut driver) = self.driver.take() {
            driver.on_error(ep, &err);
            self.driver = Some(driver);
        }
        ep.close();
    }

    fn issue_no_ep(&mut self, kind: PendingKind, command: &str) -> Result<String, String> {
        if !self.pending.can_issue() {
            let msg = format!(
                "IMAP max_pipeline ({}) exceeded",
                self.pending.max_pipeline()
            );
            self.pending_issue_error = Some(msg.clone());
            return Err(msg);
        }
        let tag = self.tags.next();
        let cmd = PendingCommand {
            tag: tag.clone(),
            kind,
            timer: None,
            cancel_flag: None,
        };
        if self.pending.insert(cmd).is_err() {
            let msg = "IMAP max_pipeline exceeded".to_string();
            self.pending_issue_error = Some(msg.clone());
            return Err(msg);
        }
        self.write_line(&format!("{tag} {command}"));
        Ok(tag)
    }

    fn quote_astring(s: &str) -> String {
        if s.is_empty() {
            return "\"\"".into();
        }
        if s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
        {
            return s.to_string();
        }
        let mut out = String::from("\"");
        for c in s.chars() {
            if c == '\\' || c == '"' {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('"');
        out
    }

    fn format_id_cmd(fields: Option<&[(&str, &str)]>) -> String {
        match fields {
            None => "ID NIL".into(),
            Some(pairs) if pairs.is_empty() => "ID NIL".into(),
            Some(pairs) => {
                let mut parts = Vec::with_capacity(pairs.len() * 2);
                for (k, v) in pairs {
                    parts.push(Self::quote_astring(k));
                    parts.push(Self::quote_astring(v));
                }
                format!("ID ({})", parts.join(" "))
            }
        }
    }

    fn format_store_flags(flags: &str) -> String {
        let f = flags.trim();
        if f.starts_with('(') {
            f.to_string()
        } else {
            format!("({f})")
        }
    }

    // ── Event dispatch ────────────────────────────────────────────────────

    fn dispatch(&mut self, event: ImapEvent, ep: &mut dyn Endpoint) {
        match event {
            ImapEvent::Continuation { text } => self.on_continuation(text, ep),
            ImapEvent::Tagged { tag, status, code, message } => {
                self.on_tagged(tag, status, code, message, ep)
            }
            ImapEvent::UntaggedOk { code, text } => self.on_untagged_ok(code, text, ep),
            ImapEvent::UntaggedNo { code, text } => {
                self.apply_status_code_if_present(code.as_deref());
                let _ = text;
            }
            ImapEvent::UntaggedBad { code, text } => {
                self.apply_status_code_if_present(code.as_deref());
                let _ = text;
            }
            ImapEvent::Bye { text, .. } => self.on_bye(text, ep),
            ImapEvent::Preauth { code, .. } => self.on_preauth(code, ep),
            ImapEvent::Capability(caps) => self.capa_buf = Some(caps),
            ImapEvent::ListEntry(entry) => self.on_list_entry(entry, ep),
            ImapEvent::StatusData(data) => self.on_status_data(data, ep),
            ImapEvent::SearchNumbers(nums) => self.on_search_numbers(nums, ep),
            ImapEvent::Exists(n) => self.on_exists(n, ep),
            ImapEvent::Recent(n) => self.on_recent(n, ep),
            ImapEvent::Expunge(n) => self.on_expunge(n, ep),
            ImapEvent::FlagsList(flags) => self.select_info.flags = flags,
            ImapEvent::Fetch(data) => self.on_fetch(data, ep),
            ImapEvent::FetchLiteralBegin { seq, section, size } => {
                self.on_literal_begin(seq, section, size, ep)
            }
            ImapEvent::FetchLiteralData(data) => self.on_literal_data(data, ep),
            ImapEvent::FetchLiteralEnd { seq } => self.on_literal_end(seq, ep),
            ImapEvent::Enabled(tokens) => self.on_enabled(tokens, ep),
            ImapEvent::Namespace(payload) => self.on_namespace(&payload, ep),
            ImapEvent::Quota(payload) => self.on_quota(&payload, ep),
            ImapEvent::QuotaRoot(payload) => self.on_quota_root(&payload, ep),
            ImapEvent::IdParams(payload) => self.on_id_params(&payload, ep),
            ImapEvent::Other => {}
        }
    }

    /// Apply a mid-session untagged `NO`/`BAD` response code the same way
    /// `OK` codes are (e.g. a `[COPYUID …]` can in principle ride any
    /// status). Greeting handling only ever sees `OK`/`PREAUTH`/`BYE` per
    /// RFC 9051, so `NO`/`BAD` never occur during `Connecting`.
    fn apply_status_code_if_present(&mut self, code: Option<&str>) {
        if let Some(c) = code {
            self.apply_untagged_status_code(c);
        }
    }

    /// Resolve the capability list that goes with a greeting/LOGIN/
    /// AUTHENTICATE completion: prefer a separately-buffered untagged
    /// `* CAPABILITY ...` line (`capa_buf`) over a `[CAPABILITY ...]`
    /// response code riding the same line, matching RFC 9051 §7.1's two
    /// delivery mechanisms. `self.caps` (the `capabilities()` accessor's
    /// backing store) is only overwritten when genuinely new data was
    /// found — matches Gumdrop's `IMAPClientProtocolHandler`, where
    /// `capabilities` is only mutated inside `parseCapabilities()`, itself
    /// only called when a CAPABILITY line/code was actually seen. The
    /// *returned* value reflects only what arrived on this reply (empty if
    /// nothing new), also matching Gumdrop's fresh `ArrayList` per call.
    fn resolve_and_promote_caps(&mut self, code: Option<&str>) -> ImapCapabilities {
        let fresh = if let Some(c) = self.capa_buf.take() {
            Some(c)
        } else if let Some(code) = code {
            if code.to_ascii_uppercase().starts_with("CAPABILITY ") {
                Some(ImapCapabilities::parse(&code["CAPABILITY ".len()..]))
            } else {
                None
            }
        } else {
            None
        };
        if let Some(ref caps) = fresh {
            self.caps = caps.clone();
        }
        fresh.unwrap_or_default()
    }

    fn apply_untagged_status_code(&mut self, code: &str) {
        let cu = code.to_ascii_uppercase();
        if cu.starts_with("COPYUID ") {
            self.last_copyuid = ImapCopyUid::parse(code);
        } else if let Some(v) = cu.strip_prefix("UIDVALIDITY ") {
            self.select_info.uid_validity = v.trim().parse().ok();
        } else if let Some(v) = cu.strip_prefix("UIDNEXT ") {
            self.select_info.uid_next = v.trim().parse().ok();
        } else if let Some(v) = cu.strip_prefix("UNSEEN ") {
            self.select_info.unseen = v.trim().parse().ok();
        } else if let Some(v) = cu.strip_prefix("HIGHESTMODSEQ ") {
            self.select_info.highest_modseq = v.trim().parse().ok();
        } else if cu.starts_with("PERMANENTFLAGS") {
            let rest = code.get("PERMANENTFLAGS".len()..).unwrap_or("").trim_start();
            self.select_info.permanent_flags = parse_flag_list(rest);
        } else if cu == "READ-WRITE" {
            self.select_info.read_write = Some(true);
        } else if cu == "READ-ONLY" {
            self.select_info.read_write = Some(false);
        }
    }

    fn on_untagged_ok(&mut self, code: Option<String>, text: String, ep: &mut dyn Endpoint) {
        if self.session == SessionState::Connecting {
            self.cancel_greeting_timer();
            self.session = SessionState::NotAuthenticated;
            let caps = self.resolve_and_promote_caps(code.as_deref());
            let mut driver = match self.driver.take() {
                Some(d) => d,
                None => return,
            };
            driver.on_greeting(self, ep, &text, false, &caps);
            self.driver = Some(driver);
            return;
        }
        self.apply_status_code_if_present(code.as_deref());
    }

    fn on_bye(&mut self, text: String, ep: &mut dyn Endpoint) {
        if self.session == SessionState::Connecting {
            self.cancel_greeting_timer();
            self.protocol_error(ep, format!("IMAP greeting BYE: {text}"));
        }
        // A mid-session BYE precedes the connection closing; no action
        // needed here — `disconnected()` will fire shortly and clean up.
    }

    fn on_preauth(&mut self, code: Option<String>, ep: &mut dyn Endpoint) {
        if self.session != SessionState::Connecting {
            return;
        }
        self.cancel_greeting_timer();
        self.session = SessionState::Authenticated;
        let caps = self.resolve_and_promote_caps(code.as_deref());
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        driver.on_authenticated(self, ep, &caps);
        self.driver = Some(driver);
    }

    fn on_list_entry(&mut self, entry: ImapListEntry, ep: &mut dyn Endpoint) {
        if self.pending.oldest_compatible(UntaggedClass::List).is_none() {
            return;
        }
        if let Some(mut driver) = self.driver.take() {
            driver.on_list_entry(&entry);
            self.driver = Some(driver);
        }
        let _ = ep;
    }

    fn on_status_data(&mut self, data: ImapStatusData, ep: &mut dyn Endpoint) {
        if self.pending.oldest_compatible(UntaggedClass::Status).is_none() {
            return;
        }
        if let Some(mut driver) = self.driver.take() {
            driver.on_status_data(&data);
            self.driver = Some(driver);
        }
        let _ = ep;
    }

    fn on_search_numbers(&mut self, nums: Vec<u32>, ep: &mut dyn Endpoint) {
        if self.pending.oldest_compatible(UntaggedClass::Search).is_none() {
            return;
        }
        if let Some(mut driver) = self.driver.take() {
            driver.on_search_numbers(&nums);
            self.driver = Some(driver);
        }
        let _ = ep;
    }

    fn on_exists(&mut self, n: u32, ep: &mut dyn Endpoint) {
        if self.select_examine_pending() {
            self.select_info.exists = n;
            return;
        }
        self.route_mailbox_exists(n, ep);
    }

    fn on_recent(&mut self, n: u32, ep: &mut dyn Endpoint) {
        if self.select_examine_pending() {
            self.select_info.recent = n;
            return;
        }
        self.route_mailbox_recent(n, ep);
    }

    fn on_expunge(&mut self, n: u32, ep: &mut dyn Endpoint) {
        if self.pending.oldest_of_kind(PendingKind::Expunge).is_some() {
            if let Some(mut driver) = self.driver.take() {
                driver.on_expunge_seq(n);
                self.driver = Some(driver);
            }
            return;
        }
        self.route_mailbox_expunge(n, ep);
    }

    fn select_examine_pending(&self) -> bool {
        self.pending
            .oldest_compatible(UntaggedClass::Exists)
            .map(|c| matches!(c.kind, PendingKind::Select | PendingKind::Examine))
            == Some(true)
    }

    fn route_mailbox_exists(&mut self, n: u32, ep: &mut dyn Endpoint) {
        let _ = ep;
        if let Some(mut driver) = self.driver.take() {
            if let Some(listener) = driver.mailbox_events() {
                listener.on_exists(n);
            }
            self.driver = Some(driver);
        }
        self.maybe_fire_idle_event(ep);
    }

    fn route_mailbox_recent(&mut self, n: u32, ep: &mut dyn Endpoint) {
        let _ = ep;
        if let Some(mut driver) = self.driver.take() {
            if let Some(listener) = driver.mailbox_events() {
                listener.on_recent(n);
            }
            self.driver = Some(driver);
        }
        self.maybe_fire_idle_event(ep);
    }

    fn route_mailbox_expunge(&mut self, n: u32, ep: &mut dyn Endpoint) {
        let _ = ep;
        if let Some(mut driver) = self.driver.take() {
            if let Some(listener) = driver.mailbox_events() {
                listener.on_expunge(n);
            }
            self.driver = Some(driver);
        }
        self.maybe_fire_idle_event(ep);
    }

    fn route_mailbox_flags(&mut self, seq: u32, flags: &[String], ep: &mut dyn Endpoint) {
        let _ = ep;
        if let Some(mut driver) = self.driver.take() {
            if let Some(listener) = driver.mailbox_events() {
                listener.on_flags(seq, flags);
            }
            self.driver = Some(driver);
        }
        self.maybe_fire_idle_event(ep);
    }

    fn maybe_fire_idle_event(&mut self, _ep: &mut dyn Endpoint) {
        if self.session != SessionState::IdleActive {
            return;
        }
        if let Some(mut driver) = self.driver.take() {
            driver.on_idle_mailbox_event(self);
            self.driver = Some(driver);
        }
    }

    fn on_fetch(&mut self, data: ImapFetchData, ep: &mut dyn Endpoint) {
        let flags_only =
            data.uid.is_none() && data.size.is_none() && data.modseq.is_none() && data.body.is_empty()
                && !data.flags.is_empty();
        if flags_only {
            if self.pending.oldest_of_kind(PendingKind::Store).is_some() {
                self.deliver_fetch_data(data, ep);
                return;
            }
            self.route_mailbox_flags(data.seq, &data.flags, ep);
            return;
        }
        if self.pending.oldest_of_kind(PendingKind::Fetch).is_some() {
            self.deliver_fetch_data(data, ep);
        }
        // Non-flags-only FETCH with no pending FETCH command: unsolicited
        // and not representable via the mailbox-event listener — dropped,
        // matching the old design's effective behaviour.
    }

    fn deliver_fetch_data(&mut self, data: ImapFetchData, ep: &mut dyn Endpoint) {
        let _ = ep;
        if let Some(mut driver) = self.driver.take() {
            driver.on_fetch_data(&data);
            self.driver = Some(driver);
        }
    }

    fn on_literal_begin(&mut self, seq: u32, section: String, size: u64, ep: &mut dyn Endpoint) {
        if self.pending.oldest_of_kind(PendingKind::Fetch).is_some() {
            if let Some(mut driver) = self.driver.take() {
                driver.on_fetch_literal_begin(ep, seq, &section, size);
                self.driver = Some(driver);
            }
        }
    }

    fn on_literal_data(&mut self, data: Vec<u8>, ep: &mut dyn Endpoint) {
        if self.pending.oldest_of_kind(PendingKind::Fetch).is_some() {
            self.arm_message_timer(ep);
            if let Some(mut driver) = self.driver.take() {
                driver.on_fetch_literal(&data, ep);
                self.driver = Some(driver);
            }
        }
    }

    fn on_literal_end(&mut self, seq: u32, ep: &mut dyn Endpoint) {
        self.cancel_message_timer();
        if self.pending.oldest_of_kind(PendingKind::Fetch).is_some() {
            if let Some(mut driver) = self.driver.take() {
                driver.on_fetch_literal_end(ep, seq);
                self.driver = Some(driver);
            }
        }
    }

    fn on_enabled(&mut self, tokens: Vec<String>, ep: &mut dyn Endpoint) {
        let _ = ep;
        if self.pending.oldest_of_kind(PendingKind::Enable).is_none() {
            return;
        }
        let refs: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
        self.enabled.enable(
            &refs,
            self.caps.condstore || self.caps.enable,
            self.caps.qresync || self.caps.enable,
        );
        let enabled = self.enabled.clone();
        if let Some(mut driver) = self.driver.take() {
            driver.on_enabled(&enabled);
            self.driver = Some(driver);
        }
    }

    fn on_namespace(&mut self, payload: &str, ep: &mut dyn Endpoint) {
        let _ = ep;
        if self.pending.oldest_of_kind(PendingKind::Namespace).is_none() {
            return;
        }
        if let Some(data) = ImapNamespaceData::parse(payload) {
            if let Some(mut driver) = self.driver.take() {
                driver.on_namespace(&data);
                self.driver = Some(driver);
            }
        }
    }

    fn on_quota(&mut self, payload: &str, ep: &mut dyn Endpoint) {
        let _ = ep;
        if self.pending.oldest_of_kind(PendingKind::Quota).is_none() {
            return;
        }
        if let Some(data) = ImapQuotaData::parse(payload) {
            if let Some(mut driver) = self.driver.take() {
                driver.on_quota(&data);
                self.driver = Some(driver);
            }
        }
    }

    fn on_quota_root(&mut self, payload: &str, ep: &mut dyn Endpoint) {
        let _ = ep;
        if self.pending.oldest_of_kind(PendingKind::Quota).is_none() {
            return;
        }
        if let Some(data) = ImapQuotaRootData::parse(payload) {
            if let Some(mut driver) = self.driver.take() {
                driver.on_quota_root(&data);
                self.driver = Some(driver);
            }
        }
    }

    fn on_id_params(&mut self, payload: &str, ep: &mut dyn Endpoint) {
        let _ = ep;
        if self.pending.oldest_of_kind(PendingKind::Id).is_none() {
            return;
        }
        let params = parse_id_params(payload);
        if let Some(mut driver) = self.driver.take() {
            driver.on_id_params(&params);
            self.driver = Some(driver);
        }
    }

    fn on_continuation(&mut self, text: String, ep: &mut dyn Endpoint) {
        let owner = self.pending.continuation_owner().map(|s| s.to_string());
        let kind = owner
            .as_ref()
            .and_then(|t| self.pending.get(t).map(|c| c.kind));
        match kind {
            Some(PendingKind::Authenticate) => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_auth_continue(self, ep, &text);
                self.driver = Some(driver);
            }
            Some(PendingKind::Append) => {
                self.pending.clear_continuation_owner();
                if let Some(data) = self.append_pending_data.take() {
                    self.write_raw(&data);
                } else {
                    let mut driver = match self.driver.take() {
                        Some(d) => d,
                        None => return,
                    };
                    driver.on_append_continue(self, ep, &text);
                    self.driver = Some(driver);
                }
            }
            Some(PendingKind::Idle) => {
                self.pending.clear_continuation_owner();
                self.session = SessionState::IdleActive;
                // Drop the stage timer while idling; DONE keeps the same tag
                // outstanding until the tagged completion arrives.
                if let Some(tag) = owner.as_ref() {
                    self.pending.cancel_timer_for(tag);
                }
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_idle_started(self, ep);
                self.driver = Some(driver);
            }
            _ => {
                self.protocol_error(ep, "unexpected IMAP continuation");
            }
        }
    }

    fn on_tagged(
        &mut self,
        tag: String,
        status: ImapStatus,
        response_code: Option<String>,
        message: String,
        ep: &mut dyn Endpoint,
    ) {
        let Some(cmd) = self.pending.complete(&tag) else {
            self.protocol_error(ep, format!("unknown IMAP tag: {tag}"));
            return;
        };
        self.cancel_message_timer();

        if let Some(ref code) = response_code {
            let cu = code.to_ascii_uppercase();
            if cu.starts_with("COPYUID ") {
                self.last_copyuid = ImapCopyUid::parse(code);
            } else if cu.starts_with("APPENDUID ") {
                self.last_appenduid = ImapAppendUid::parse(code);
            }
        }

        match cmd.kind {
            PendingKind::Capability => {
                let caps = if let Some(c) = self.capa_buf.take() {
                    c
                } else if let Some(ref code) = response_code {
                    if code.to_ascii_uppercase().starts_with("CAPABILITY ") {
                        ImapCapabilities::parse(&code["CAPABILITY ".len()..])
                    } else {
                        ImapCapabilities::default()
                    }
                } else {
                    ImapCapabilities::default()
                };
                self.caps = caps.clone();
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_capability(self, ep, &caps);
                self.driver = Some(driver);
            }
            PendingKind::Starttls => match status {
                ImapStatus::Ok => {
                    if let (Some(connector), Some(name)) =
                        (self.tls_connector.clone(), self.tls_server_name.clone())
                    {
                        self.session = SessionState::PendingTls;
                        match ep.start_client_tls(connector, &name) {
                            Ok(()) => {}
                            Err(e) => {
                                self.protocol_error(ep, format!("start_client_tls: {e}"));
                            }
                        }
                    } else {
                        self.protocol_error(ep, "STARTTLS OK but no TLS connector configured");
                    }
                }
                ImapStatus::No | ImapStatus::Bad => {
                    let mut driver = match self.driver.take() {
                        Some(d) => d,
                        None => return,
                    };
                    driver.on_tls_unavailable(self, ep, &message);
                    self.driver = Some(driver);
                }
            },
            PendingKind::Login | PendingKind::Authenticate => match status {
                ImapStatus::Ok => {
                    self.session = SessionState::Authenticated;
                    let caps = self.resolve_and_promote_caps(response_code.as_deref());
                    let mut driver = match self.driver.take() {
                        Some(d) => d,
                        None => return,
                    };
                    driver.on_authenticated(self, ep, &caps);
                    self.driver = Some(driver);
                }
                ImapStatus::No | ImapStatus::Bad => {
                    let mut driver = match self.driver.take() {
                        Some(d) => d,
                        None => return,
                    };
                    driver.on_auth_failed(self, ep, &message);
                    self.driver = Some(driver);
                }
            },
            PendingKind::Select | PendingKind::Examine => match status {
                ImapStatus::Ok => {
                    self.session = SessionState::Selected;
                    let read_only = self.select_info.read_write == Some(false)
                        || cmd.kind == PendingKind::Examine;
                    let info = self.select_info.clone();
                    let mut driver = match self.driver.take() {
                        Some(d) => d,
                        None => return,
                    };
                    driver.on_selected(self, ep, &info, read_only);
                    self.driver = Some(driver);
                }
                ImapStatus::No | ImapStatus::Bad => {
                    let mut driver = match self.driver.take() {
                        Some(d) => d,
                        None => return,
                    };
                    driver.on_select_failed(self, ep, &message);
                    self.driver = Some(driver);
                }
            },
            PendingKind::Fetch => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_fetch_complete(self, ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::Search => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_search_complete(self, ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::List => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_list_complete(self, ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::Status => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_status_complete(self, ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::Append => {
                let appenduid = self.last_appenduid.take();
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_append_complete(self, ep, status, appenduid.as_ref(), &message);
                self.driver = Some(driver);
            }
            PendingKind::Store => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_store_complete(self, ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::Copy => {
                let copyuid = self.last_copyuid.take();
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_copy_complete(self, ep, status, copyuid.as_ref(), &message);
                self.driver = Some(driver);
            }
            PendingKind::Move => {
                let copyuid = self.last_copyuid.take();
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_move_complete(self, ep, status, copyuid.as_ref(), &message);
                self.driver = Some(driver);
            }
            PendingKind::Expunge => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_expunge_complete(self, ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::Idle => {
                self.session = if self.was_selected {
                    SessionState::Selected
                } else {
                    SessionState::Authenticated
                };
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_idle_complete(self, ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::Enable => {
                let enabled = self.enabled.clone();
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_enable_complete(self, ep, status, &enabled, &message);
                self.driver = Some(driver);
            }
            PendingKind::Namespace => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_namespace_complete(self, ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::Id => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_id_complete(ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::Quota => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_quota_complete(self, ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::Close | PendingKind::Unselect => {
                if status == ImapStatus::Ok {
                    self.session = SessionState::Authenticated;
                }
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_deselect_complete(self, ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::Logout => {
                self.session = SessionState::Logout;
                ep.close();
            }
            PendingKind::MailboxOp => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_mailbox_op_complete(self, ep, status, &message);
                self.driver = Some(driver);
            }
            PendingKind::Other => {
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_command_complete(ep, &tag, status, response_code.as_deref(), &message);
                self.driver = Some(driver);
            }
        }
    }
}

// ── State trait impls ─────────────────────────────────────────────────────────

impl ImapClientNotAuthenticated for ImapClientEndpoint {
    fn capability(&mut self) {
        let _ = self.issue_no_ep(PendingKind::Capability, "CAPABILITY");
    }

    fn login(&mut self, username: &str, password: &str) {
        let cmd = format!(
            "LOGIN {} {}",
            Self::quote_astring(username),
            Self::quote_astring(password)
        );
        let _ = self.issue_no_ep(PendingKind::Login, &cmd);
    }

    fn authenticate(&mut self, mechanism: &str, initial: Option<&[u8]>) {
        let mech = mechanism.to_ascii_uppercase();
        if let Some(raw) = initial {
            let b64 = base64::encode(raw);
            let _ = self.issue_no_ep(
                PendingKind::Authenticate,
                &format!("AUTHENTICATE {mech} {b64}"),
            );
        } else {
            let _ = self.issue_no_ep(PendingKind::Authenticate, &format!("AUTHENTICATE {mech}"));
        }
    }

    fn starttls(&mut self) {
        let _ = self.issue_no_ep(PendingKind::Starttls, "STARTTLS");
    }

    fn id(&mut self, fields: Option<&[(&str, &str)]>) {
        let _ = self.issue_no_ep(PendingKind::Id, &Self::format_id_cmd(fields));
    }

    fn logout(&mut self) {
        let _ = self.issue_no_ep(PendingKind::Logout, "LOGOUT");
    }

    fn capabilities(&self) -> &ImapCapabilities {
        &self.caps
    }
}

impl ImapClientPostStarttls for ImapClientEndpoint {}

impl ImapClientAuthExchange for ImapClientEndpoint {
    fn respond(&mut self, response: &[u8]) {
        let b64 = base64::encode(response);
        self.write_line(&b64);
    }

    fn abort(&mut self) {
        self.write_line("*");
    }
}

impl ImapClientAuthenticated for ImapClientEndpoint {
    fn capability(&mut self) {
        let _ = self.issue_no_ep(PendingKind::Capability, "CAPABILITY");
    }

    fn select(&mut self, mailbox: &str) {
        self.select_info = ImapMailboxInfo {
            name: mailbox.to_string(),
            ..ImapMailboxInfo::default()
        };
        let cmd = format!("SELECT {}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::Select, &cmd);
    }

    fn examine(&mut self, mailbox: &str) {
        self.select_info = ImapMailboxInfo {
            name: mailbox.to_string(),
            ..ImapMailboxInfo::default()
        };
        let cmd = format!("EXAMINE {}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::Examine, &cmd);
    }

    fn list(&mut self, reference: &str, pattern: &str) {
        let cmd = format!(
            "LIST {} {}",
            Self::quote_astring(reference),
            Self::quote_astring(pattern)
        );
        let _ = self.issue_no_ep(PendingKind::List, &cmd);
    }

    fn lsub(&mut self, reference: &str, pattern: &str) {
        let cmd = format!(
            "LSUB {} {}",
            Self::quote_astring(reference),
            Self::quote_astring(pattern)
        );
        let _ = self.issue_no_ep(PendingKind::List, &cmd);
    }

    fn status(&mut self, mailbox: &str, items: &str) {
        let items = items.trim();
        let items = if items.starts_with('(') {
            items.to_string()
        } else {
            format!("({items})")
        };
        let cmd = format!("STATUS {} {items}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::Status, &cmd);
    }

    fn append(
        &mut self,
        mailbox: &str,
        flags: Option<&str>,
        date: Option<&str>,
        size: u64,
        use_literal_minus: bool,
    ) {
        let mut cmd = format!("APPEND {}", Self::quote_astring(mailbox));
        if let Some(f) = flags {
            cmd.push(' ');
            if f.starts_with('(') {
                cmd.push_str(f);
            } else {
                cmd.push('(');
                cmd.push_str(f);
                cmd.push(')');
            }
        }
        if let Some(d) = date {
            cmd.push_str(&format!(" \"{d}\""));
        }
        self.append_literal_minus = use_literal_minus && size <= 4096;
        if self.append_literal_minus {
            cmd.push_str(&format!(" {{{size}+}}"));
        } else {
            cmd.push_str(&format!(" {{{size}}}"));
        }
        let _ = self.issue_no_ep(PendingKind::Append, &cmd);
    }

    fn namespace(&mut self) {
        let _ = self.issue_no_ep(PendingKind::Namespace, "NAMESPACE");
    }

    fn enable(&mut self, features: &str) {
        let _ = self.issue_no_ep(PendingKind::Enable, &format!("ENABLE {features}"));
    }

    fn id(&mut self, fields: Option<&[(&str, &str)]>) {
        let _ = self.issue_no_ep(PendingKind::Id, &Self::format_id_cmd(fields));
    }

    fn get_quota(&mut self, root: &str) {
        let cmd = format!("GETQUOTA {}", Self::quote_astring(root));
        let _ = self.issue_no_ep(PendingKind::Quota, &cmd);
    }

    fn get_quota_root(&mut self, mailbox: &str) {
        let cmd = format!("GETQUOTAROOT {}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::Quota, &cmd);
    }

    fn set_quota(&mut self, root: &str, resources: &str) {
        let res = resources.trim();
        let res = if res.starts_with('(') {
            res.to_string()
        } else {
            format!("({res})")
        };
        let cmd = format!("SETQUOTA {} {res}", Self::quote_astring(root));
        let _ = self.issue_no_ep(PendingKind::Quota, &cmd);
    }

    fn idle(&mut self) {
        self.was_selected = self.session == SessionState::Selected;
        self.session = SessionState::IdleSent;
        let _ = self.issue_no_ep(PendingKind::Idle, "IDLE");
    }

    fn noop(&mut self) {
        let _ = self.issue_no_ep(PendingKind::Other, "NOOP");
    }

    fn create(&mut self, mailbox: &str) {
        let cmd = format!("CREATE {}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::MailboxOp, &cmd);
    }

    fn delete(&mut self, mailbox: &str) {
        let cmd = format!("DELETE {}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::MailboxOp, &cmd);
    }

    fn rename(&mut self, from: &str, to: &str) {
        let cmd = format!(
            "RENAME {} {}",
            Self::quote_astring(from),
            Self::quote_astring(to)
        );
        let _ = self.issue_no_ep(PendingKind::MailboxOp, &cmd);
    }

    fn subscribe(&mut self, mailbox: &str) {
        let cmd = format!("SUBSCRIBE {}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::MailboxOp, &cmd);
    }

    fn unsubscribe(&mut self, mailbox: &str) {
        let cmd = format!("UNSUBSCRIBE {}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::MailboxOp, &cmd);
    }

    fn logout(&mut self) {
        let _ = self.issue_no_ep(PendingKind::Logout, "LOGOUT");
    }

    fn capabilities(&self) -> &ImapCapabilities {
        &self.caps
    }

    fn enabled_features(&self) -> &ImapEnabledFeatures {
        &self.enabled
    }
}

impl ImapClientAppend for ImapClientEndpoint {
    fn send_literal(&mut self, data: &[u8]) {
        if self.append_literal_minus {
            self.write_raw(data);
            self.append_literal_minus = false;
            self.pending.clear_continuation_owner();
        } else if self.pending.continuation_owner().is_some() {
            self.append_pending_data = Some(data.to_vec());
        } else {
            self.write_raw(data);
        }
    }
}

impl ImapClientSelected for ImapClientEndpoint {
    fn fetch(&mut self, sequence_set: &str, items: &str) {
        let cmd = format!("FETCH {sequence_set} {items}");
        let _ = self.issue_no_ep(PendingKind::Fetch, &cmd);
    }

    fn uid_fetch(&mut self, sequence_set: &str, items: &str) {
        let cmd = format!("UID FETCH {sequence_set} {items}");
        let _ = self.issue_no_ep(PendingKind::Fetch, &cmd);
    }

    fn search(&mut self, criteria: &str) {
        let cmd = format!("SEARCH {criteria}");
        let _ = self.issue_no_ep(PendingKind::Search, &cmd);
    }

    fn uid_search(&mut self, criteria: &str) {
        let cmd = format!("UID SEARCH {criteria}");
        let _ = self.issue_no_ep(PendingKind::Search, &cmd);
    }

    fn store(&mut self, sequence_set: &str, action: &str, flags: &str) {
        let cmd = format!(
            "STORE {sequence_set} {action} {}",
            Self::format_store_flags(flags)
        );
        let _ = self.issue_no_ep(PendingKind::Store, &cmd);
    }

    fn uid_store(&mut self, sequence_set: &str, action: &str, flags: &str) {
        let cmd = format!(
            "UID STORE {sequence_set} {action} {}",
            Self::format_store_flags(flags)
        );
        let _ = self.issue_no_ep(PendingKind::Store, &cmd);
    }

    fn copy(&mut self, sequence_set: &str, mailbox: &str) {
        self.last_copyuid = None;
        let cmd = format!("COPY {sequence_set} {}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::Copy, &cmd);
    }

    fn uid_copy(&mut self, sequence_set: &str, mailbox: &str) {
        self.last_copyuid = None;
        let cmd = format!("UID COPY {sequence_set} {}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::Copy, &cmd);
    }

    fn move_(&mut self, sequence_set: &str, mailbox: &str) {
        self.last_copyuid = None;
        let cmd = format!("MOVE {sequence_set} {}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::Move, &cmd);
    }

    fn uid_move(&mut self, sequence_set: &str, mailbox: &str) {
        self.last_copyuid = None;
        let cmd = format!("UID MOVE {sequence_set} {}", Self::quote_astring(mailbox));
        let _ = self.issue_no_ep(PendingKind::Move, &cmd);
    }

    fn expunge(&mut self) {
        let _ = self.issue_no_ep(PendingKind::Expunge, "EXPUNGE");
    }

    fn uid_expunge(&mut self, uid_set: &str) {
        let _ = self.issue_no_ep(PendingKind::Expunge, &format!("UID EXPUNGE {uid_set}"));
    }

    fn close(&mut self) {
        let _ = self.issue_no_ep(PendingKind::Close, "CLOSE");
    }

    fn unselect(&mut self) {
        let _ = self.issue_no_ep(PendingKind::Unselect, "UNSELECT");
    }
}

impl ImapClientIdle for ImapClientEndpoint {
    fn done(&mut self) {
        if matches!(
            self.session,
            SessionState::IdleActive | SessionState::IdleSent
        ) {
            self.write_line("DONE");
            // Re-arm stage timer on the outstanding Idle pending command.
            // Completing will happen on tagged OK.
        }
    }
}

// ── ProtocolHandler ───────────────────────────────────────────────────────────

impl ProtocolHandler for ImapClientEndpoint {
    fn connected(&mut self, ep: &mut dyn Endpoint) {
        if self.implicit_tls_pending {
            return;
        }
        self.arm_greeting_timer(ep);
    }

    fn receive(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) {
        if matches!(self.session, SessionState::Closed | SessionState::Error) {
            *data = &[];
            return;
        }
        let events = match self.lexer.feed(data) {
            Ok(e) => e,
            Err(e) => {
                self.protocol_error(ep, e.to_string());
                return;
            }
        };
        for event in events {
            if matches!(self.session, SessionState::Closed | SessionState::Error) {
                break;
            }
            self.dispatch(event, ep);
            self.flush_outbound(ep);
        }
    }

    fn security_established(&mut self, ep: &mut dyn Endpoint, _info: &SecurityInfo) {
        if self.implicit_tls_pending {
            self.implicit_tls_pending = false;
            self.arm_greeting_timer(ep);
            return;
        }
        if self.session == SessionState::PendingTls {
            self.session = SessionState::NotAuthenticated;
            let mut driver = match self.driver.take() {
                Some(d) => d,
                None => return,
            };
            driver.on_tls_established(self, ep);
            self.driver = Some(driver);
            self.flush_outbound(ep);
        }
    }

    fn disconnected(&mut self, ep: &mut dyn Endpoint) {
        self.cancel_greeting_timer();
        self.cancel_message_timer();
        self.pending.drain_all();
        if matches!(self.session, SessionState::Closed | SessionState::Error) {
            return;
        }
        self.session = SessionState::Closed;
        if let Some(mut driver) = self.driver.take() {
            driver.on_disconnected(ep);
            self.driver = Some(driver);
        }
    }

    fn error(&mut self, ep: &mut dyn Endpoint, err: &io::Error) {
        self.cancel_greeting_timer();
        self.cancel_message_timer();
        self.pending.drain_all();
        if err.kind() == io::ErrorKind::TimedOut {
            self.session = SessionState::Error;
            if let Some(mut driver) = self.driver.take() {
                driver.on_timeout(ep);
                self.driver = Some(driver);
            }
            ep.close();
            return;
        }
        self.session = SessionState::Error;
        if let Some(mut driver) = self.driver.take() {
            driver.on_error(ep, err);
            self.driver = Some(driver);
        }
        ep.close();
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_flag_list(s: &str) -> Vec<String> {
    let s = s.trim();
    let s = s
        .strip_prefix('(')
        .and_then(|x| x.strip_suffix(')'))
        .unwrap_or(s);
    s.split_whitespace().map(|f| f.to_string()).collect()
}

/// Parse the bounded-captured `ID` payload (already stripped of the `ID `
/// keyword by the lexer): `(key value key value …)` or `NIL`.
fn parse_id_params(raw: &str) -> Vec<(String, String)> {
    let rest = raw.trim();
    if rest.eq_ignore_ascii_case("NIL") {
        return Vec::new();
    }
    let inner = rest
        .strip_prefix('(')
        .and_then(|x| x.strip_suffix(')'))
        .unwrap_or(rest);
    let mut out = Vec::new();
    let mut toks = tokenize_astring_list(inner);
    while toks.len() >= 2 {
        let k = toks.remove(0);
        let v = toks.remove(0);
        out.push((k, v));
    }
    out
}

fn tokenize_astring_list(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.starts_with('"') {
            if let Some(end) = find_closing_quote(rest) {
                out.push(unquote_simple(&rest[..=end]));
                rest = rest[end + 1..].trim_start();
                continue;
            }
        }
        let mut parts = rest.splitn(2, char::is_whitespace);
        let tok = parts.next().unwrap_or("");
        rest = parts.next().unwrap_or("").trim_start();
        if !tok.is_empty() {
            out.push(tok.to_string());
        } else {
            break;
        }
    }
    out
}

fn find_closing_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn unquote_simple(s: &str) -> String {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::pending::DEFAULT_MAX_PIPELINE;
    use crate::client::state::ImapClientAuthenticated;
    use hopf_core::ConnHandle;
    use std::sync::{Arc, Mutex};

    struct FakeEp {
        sent: Vec<u8>,
        secure: SecurityInfo,
        handle: ConnHandle,
        closed: bool,
        fail_kind: Option<io::ErrorKind>,
    }

    impl FakeEp {
        fn new() -> Self {
            Self {
                sent: Vec::new(),
                secure: SecurityInfo::plaintext(),
                handle: ConnHandle::from_execute(Arc::new(|task| task())),
                closed: false,
                fail_kind: None,
            }
        }

        fn sent_str(&self) -> String {
            String::from_utf8_lossy(&self.sent).into_owned()
        }
    }

    impl Endpoint for FakeEp {
        fn send(&mut self, data: &[u8]) {
            self.sent.extend_from_slice(data);
        }
        fn is_open(&self) -> bool {
            !self.closed
        }
        fn is_closing(&self) -> bool {
            false
        }
        fn close(&mut self) {
            self.closed = true;
        }
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }
        fn remote_addr(&self) -> io::Result<std::net::SocketAddr> {
            self.local_addr()
        }
        fn security_info(&self) -> &SecurityInfo {
            &self.secure
        }
        fn start_tls(&mut self) -> Result<(), hopf_core::StartTlsError> {
            Err(hopf_core::StartTlsError::Unsupported)
        }
        fn start_client_tls(
            &mut self,
            _c: SharedTlsConnector,
            _n: &str,
        ) -> Result<(), hopf_core::StartTlsError> {
            Ok(())
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _cb: Option<hopf_core::WriteReadyCallback>) {}
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn schedule_timer(&self, _delay: Duration, _cb: Box<dyn FnOnce() + Send>) -> TimerHandle {
            TimerHandle::from_cancel(|| {})
        }
        fn handle(&self) -> ConnHandle {
            self.handle.clone()
        }
        fn fail(&mut self, err: io::Error) {
            self.fail_kind = Some(err.kind());
            self.closed = true;
        }
    }

    struct RecordingDriver {
        events: Arc<Mutex<Vec<String>>>,
        listener: RecordingListener,
    }

    struct RecordingListener {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl super::super::handlers::MailboxEventListener for RecordingListener {
        fn on_exists(&mut self, count: u32) {
            self.events.lock().unwrap().push(format!("exists:{count}"));
        }
        fn on_recent(&mut self, count: u32) {
            self.events.lock().unwrap().push(format!("recent:{count}"));
        }
        fn on_expunge(&mut self, seq: u32) {
            self.events.lock().unwrap().push(format!("expunge:{seq}"));
        }
        fn on_flags(&mut self, seq: u32, flags: &[String]) {
            self.events
                .lock()
                .unwrap()
                .push(format!("flags:{seq}:{}", flags.join(",")));
        }
    }

    impl ImapClientDriver for RecordingDriver {
        fn mailbox_events(
            &mut self,
        ) -> Option<&mut dyn super::super::handlers::MailboxEventListener> {
            Some(&mut self.listener)
        }
        fn on_greeting(
            &mut self,
            _a: &mut dyn ImapClientNotAuthenticated,
            _e: &mut dyn Endpoint,
            _t: &str,
            _p: bool,
            caps: &ImapCapabilities,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("greeting:starttls={}", caps.starttls));
        }
        fn on_capability(
            &mut self,
            _a: &mut dyn ImapClientNotAuthenticated,
            _e: &mut dyn Endpoint,
            _c: &ImapCapabilities,
        ) {
        }
        fn on_tls_established(
            &mut self,
            _p: &mut dyn ImapClientPostStarttls,
            _e: &mut dyn Endpoint,
        ) {
        }
        fn on_tls_unavailable(
            &mut self,
            _a: &mut dyn ImapClientNotAuthenticated,
            _e: &mut dyn Endpoint,
            _m: &str,
        ) {
        }
        fn on_authenticated(
            &mut self,
            _s: &mut dyn ImapClientAuthenticated,
            _e: &mut dyn Endpoint,
            caps: &ImapCapabilities,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("authenticated:idle={}", caps.idle));
        }
        fn on_auth_failed(
            &mut self,
            _a: &mut dyn ImapClientNotAuthenticated,
            _e: &mut dyn Endpoint,
            _m: &str,
        ) {
        }
        fn on_mailbox_op_complete(
            &mut self,
            _s: &mut dyn ImapClientAuthenticated,
            _e: &mut dyn Endpoint,
            status: ImapStatus,
            _m: &str,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("mailbox_op_done:{status:?}"));
        }
        fn on_auth_continue(
            &mut self,
            _x: &mut dyn ImapClientAuthExchange,
            _e: &mut dyn Endpoint,
            _t: &str,
        ) {
        }
        fn on_selected(
            &mut self,
            _s: &mut dyn ImapClientSelected,
            _e: &mut dyn Endpoint,
            _i: &ImapMailboxInfo,
            _r: bool,
        ) {
        }
        fn on_select_failed(
            &mut self,
            _s: &mut dyn ImapClientAuthenticated,
            _e: &mut dyn Endpoint,
            _m: &str,
        ) {
        }
        fn on_fetch_literal_begin(
            &mut self,
            _e: &mut dyn Endpoint,
            seq: u32,
            section: &str,
            size: u64,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("lit_begin:{seq}:{section}:{size}"));
        }
        fn on_fetch_literal(&mut self, data: &[u8], _e: &mut dyn Endpoint) {
            self.events
                .lock()
                .unwrap()
                .push(format!("lit:{}", data.len()));
        }
        fn on_fetch_literal_end(&mut self, _e: &mut dyn Endpoint, seq: u32) {
            self.events.lock().unwrap().push(format!("lit_end:{seq}"));
        }
        fn on_fetch_data(&mut self, data: &ImapFetchData) {
            self.events
                .lock()
                .unwrap()
                .push(format!("fetch_data:{}", data.seq));
        }
        fn on_fetch_complete(
            &mut self,
            _s: &mut dyn ImapClientSelected,
            _e: &mut dyn Endpoint,
            status: ImapStatus,
            _m: &str,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("fetch_done:{status:?}"));
        }
        fn on_status_data(&mut self, data: &ImapStatusData) {
            self.events.lock().unwrap().push(format!(
                "status_data:{}:{}",
                data.mailbox,
                data.messages.unwrap_or(0)
            ));
        }
        fn on_status_complete(
            &mut self,
            _s: &mut dyn ImapClientAuthenticated,
            _e: &mut dyn Endpoint,
            status: ImapStatus,
            _m: &str,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("status_done:{status:?}"));
        }
        fn on_list_entry(&mut self, entry: &ImapListEntry) {
            self.events
                .lock()
                .unwrap()
                .push(format!("list_entry:{}", entry.name));
        }
        fn on_list_complete(
            &mut self,
            _s: &mut dyn ImapClientAuthenticated,
            _e: &mut dyn Endpoint,
            status: ImapStatus,
            _m: &str,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("list_done:{status:?}"));
        }
        fn on_search_numbers(&mut self, numbers: &[u32]) {
            self.events.lock().unwrap().push(format!(
                "search:{}",
                numbers
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        fn on_search_complete(
            &mut self,
            _s: &mut dyn ImapClientSelected,
            _e: &mut dyn Endpoint,
            status: ImapStatus,
            _m: &str,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("search_done:{status:?}"));
        }
        fn on_store_complete(
            &mut self,
            _s: &mut dyn ImapClientSelected,
            _e: &mut dyn Endpoint,
            status: ImapStatus,
            _m: &str,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("store_done:{status:?}"));
        }
        fn on_move_complete(
            &mut self,
            _s: &mut dyn ImapClientSelected,
            _e: &mut dyn Endpoint,
            status: ImapStatus,
            copyuid: Option<&ImapCopyUid>,
            _m: &str,
        ) {
            let cu = copyuid
                .map(|c| format!("{}:{}", c.source_uids, c.dest_uids))
                .unwrap_or_default();
            self.events
                .lock()
                .unwrap()
                .push(format!("move_done:{status:?}:{cu}"));
        }
        fn on_enabled(&mut self, features: &ImapEnabledFeatures) {
            self.events.lock().unwrap().push(format!(
                "enabled:condstore={}:qresync={}",
                features.condstore, features.qresync
            ));
        }
        fn on_enable_complete(
            &mut self,
            _s: &mut dyn ImapClientAuthenticated,
            _e: &mut dyn Endpoint,
            status: ImapStatus,
            enabled: &ImapEnabledFeatures,
            _m: &str,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("enable_done:{status:?}:{}", enabled.condstore));
        }
        fn on_idle_started(&mut self, _i: &mut dyn ImapClientIdle, _e: &mut dyn Endpoint) {
            self.events.lock().unwrap().push("idle_started".into());
        }
        fn on_idle_complete(
            &mut self,
            _s: &mut dyn ImapClientSelected,
            _e: &mut dyn Endpoint,
            status: ImapStatus,
            _m: &str,
        ) {
            self.events
                .lock()
                .unwrap()
                .push(format!("idle_done:{status:?}"));
        }
        fn on_append_continue(
            &mut self,
            _a: &mut dyn ImapClientAppend,
            _e: &mut dyn Endpoint,
            _t: &str,
        ) {
        }
        fn on_append_complete(
            &mut self,
            _s: &mut dyn ImapClientAuthenticated,
            _e: &mut dyn Endpoint,
            status: ImapStatus,
            appenduid: Option<&ImapAppendUid>,
            _m: &str,
        ) {
            let au = appenduid
                .map(|a| format!("{}:{}", a.uid_validity, a.uid))
                .unwrap_or_default();
            self.events
                .lock()
                .unwrap()
                .push(format!("append_done:{status:?}:{au}"));
        }
        fn on_error(&mut self, _e: &mut dyn Endpoint, err: &io::Error) {
            self.events.lock().unwrap().push(format!("err:{err}"));
        }
        fn on_timeout(&mut self, _e: &mut dyn Endpoint) {
            self.events.lock().unwrap().push("timeout".into());
        }
        fn on_disconnected(&mut self, _e: &mut dyn Endpoint) {
            self.events.lock().unwrap().push("disconnected".into());
        }
    }

    struct Factory(Arc<Mutex<Vec<String>>>);

    impl ImapClientHandlerFactory for Factory {
        fn create(&self) -> Box<dyn ImapClientDriver> {
            let events = Arc::clone(&self.0);
            Box::new(RecordingDriver {
                events: Arc::clone(&events),
                listener: RecordingListener { events },
            })
        }
    }

    fn make_ep(log: &Arc<Mutex<Vec<String>>>) -> ImapClientEndpoint {
        ImapClientEndpoint::new(
            &Factory(Arc::clone(log)),
            Duration::from_secs(60),
            Duration::from_secs(600),
            Duration::from_secs(30),
            None,
            None,
            false,
            DEFAULT_MAX_PIPELINE,
        )
    }

    fn feed(ep: &mut ImapClientEndpoint, fake: &mut FakeEp, wire: &[u8]) {
        let mut data = wire;
        ProtocolHandler::receive(ep, fake, &mut data);
    }

    #[test]
    fn fetch_vs_exists_routing() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep_handler = make_ep(&log);
        ep_handler.session = SessionState::Selected;
        let _ = ep_handler.issue_no_ep(PendingKind::Fetch, "FETCH 1 BODY[]");

        let mut fake = FakeEp::new();
        feed(
            &mut ep_handler,
            &mut fake,
            b"* 5 EXISTS\r\n* 1 FETCH (FLAGS (\\Seen) BODY[] {3}\r\nabc)\r\nA000 OK done\r\n",
        );

        let events = log.lock().unwrap().clone();
        assert!(
            events.iter().any(|e| e == "exists:5"),
            "EXISTS should hit listener: {events:?}"
        );
        assert!(
            events.iter().any(|e| e == "fetch_data:1"),
            "FETCH should hit body consumer: {events:?}"
        );
        assert!(
            events.iter().any(|e| e.starts_with("fetch_done")),
            "tagged OK should complete fetch: {events:?}"
        );
        assert!(
            events.iter().any(|e| e == "lit_begin:1::3"),
            "literal begin should carry seq/section/size: {events:?}"
        );
        assert!(events.iter().any(|e| e == "lit:3"), "{events:?}");
        assert!(
            events.iter().any(|e| e == "lit_end:1"),
            "literal end should carry seq: {events:?}"
        );
    }

    #[test]
    fn unknown_tag_is_protocol_error() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep_handler = make_ep(&log);
        ep_handler.session = SessionState::Authenticated;
        let mut fake = FakeEp::new();
        feed(&mut ep_handler, &mut fake, b"Z999 OK surprise\r\n");
        let events = log.lock().unwrap().clone();
        assert!(
            events.iter().any(|e| e.starts_with("err:")),
            "unknown tag must error: {events:?}"
        );
    }

    #[test]
    fn concurrent_status_list_out_of_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        ep.session = SessionState::Authenticated;
        let mut fake = FakeEp::new();
        // Issue STATUS then LIST before either completes.
        ImapClientAuthenticated::status(&mut ep, "INBOX", "MESSAGES");
        ImapClientAuthenticated::list(&mut ep, "", "*");
        assert_eq!(ep.pending_len(), 2);
        let sent = fake.sent_str(); // nothing flushed yet
        let _ = sent;
        ep.flush_outbound(&mut fake);
        let wire_out = fake.sent_str();
        assert!(wire_out.contains("STATUS"));
        assert!(wire_out.contains("LIST"));
        // Replies out of order: LIST data first, then STATUS, then tagged LIST, then STATUS.
        feed(
            &mut ep,
            &mut fake,
            b"* LIST (\\HasNoChildren) \"/\" INBOX\r\n\
              * STATUS INBOX (MESSAGES 3)\r\n\
              A001 OK LIST done\r\n\
              A000 OK STATUS done\r\n",
        );
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "list_entry:INBOX"), "{events:?}");
        assert!(
            events.iter().any(|e| e == "status_data:INBOX:3"),
            "{events:?}"
        );
        assert!(
            events.iter().any(|e| e.starts_with("list_done")),
            "{events:?}"
        );
        assert!(
            events.iter().any(|e| e.starts_with("status_done")),
            "{events:?}"
        );
        assert_eq!(ep.pending_len(), 0);
    }

    #[test]
    fn idle_lifecycle_done_and_events() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        ep.session = SessionState::Selected;
        let mut fake = FakeEp::new();
        ImapClientAuthenticated::idle(&mut ep);
        ep.flush_outbound(&mut fake);
        assert!(fake.sent_str().contains("IDLE"));
        assert_eq!(ep.session, SessionState::IdleSent);

        feed(&mut ep, &mut fake, b"+ idling\r\n");
        assert!(ep.is_idle_active());
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "idle_started"), "{events:?}");

        feed(
            &mut ep,
            &mut fake,
            b"* 4 EXISTS\r\n* 2 EXPUNGE\r\n* 1 FETCH (FLAGS (\\Seen))\r\n",
        );
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "exists:4"), "{events:?}");
        assert!(events.iter().any(|e| e == "expunge:2"), "{events:?}");
        assert!(
            events.iter().any(|e| e.starts_with("flags:1:")),
            "{events:?}"
        );

        ImapClientIdle::done(&mut ep);
        ep.flush_outbound(&mut fake);
        assert!(fake.sent_str().contains("DONE"));
        feed(&mut ep, &mut fake, b"A000 OK IDLE terminated\r\n");
        assert_eq!(ep.session, SessionState::Selected);
        let events = log.lock().unwrap().clone();
        assert!(
            events.iter().any(|e| e.starts_with("idle_done")),
            "{events:?}"
        );
    }

    #[test]
    fn search_store_move_callbacks() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        ep.session = SessionState::Selected;
        let mut fake = FakeEp::new();

        ImapClientSelected::search(&mut ep, "ALL");
        ep.flush_outbound(&mut fake);
        feed(&mut ep, &mut fake, b"* SEARCH 1 2 9\r\nA000 OK SEARCH\r\n");
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "search:1,2,9"), "{events:?}");
        assert!(
            events.iter().any(|e| e.starts_with("search_done")),
            "{events:?}"
        );

        ImapClientSelected::store(&mut ep, "1", "+FLAGS", "\\Seen");
        ep.flush_outbound(&mut fake);
        feed(
            &mut ep,
            &mut fake,
            b"* 1 FETCH (FLAGS (\\Seen))\r\nA001 OK STORE\r\n",
        );
        let events = log.lock().unwrap().clone();
        assert!(
            events.iter().any(|e| e.starts_with("store_done")),
            "{events:?}"
        );

        ImapClientSelected::move_(&mut ep, "1", "Archive");
        ep.flush_outbound(&mut fake);
        feed(&mut ep, &mut fake, b"A002 OK [COPYUID 1 1 99] Moved\r\n");
        let events = log.lock().unwrap().clone();
        assert!(
            events
                .iter()
                .any(|e| e.contains("move_done") && e.contains("1:99")),
            "{events:?}"
        );
    }

    #[test]
    fn greeting_and_login_surface_capabilities() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        let mut fake = FakeEp::new();

        feed(&mut ep, &mut fake, b"* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] Ready\r\n");
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "greeting:starttls=true"), "{events:?}");

        ImapClientNotAuthenticated::login(&mut ep, "alice", "secret");
        ep.flush_outbound(&mut fake);
        feed(
            &mut ep,
            &mut fake,
            b"A000 OK [CAPABILITY IMAP4rev1 IDLE] LOGIN completed\r\n",
        );
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "authenticated:idle=true"), "{events:?}");
    }

    #[test]
    fn append_surfaces_appenduid() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        ep.session = SessionState::Authenticated;
        let mut fake = FakeEp::new();

        ImapClientAuthenticated::append(&mut ep, "INBOX", Some("\\Seen"), None, 5, true);
        ep.flush_outbound(&mut fake);
        let wire_out = fake.sent_str();
        assert!(wire_out.contains("APPEND"));
        assert!(wire_out.contains("{5+}"));
        ImapClientAppend::send_literal(&mut ep, b"hello");
        ep.flush_outbound(&mut fake);

        feed(&mut ep, &mut fake, b"A000 OK [APPENDUID 38505 3956] APPEND completed\r\n");
        let events = log.lock().unwrap().clone();
        assert!(
            events
                .iter()
                .any(|e| e.contains("append_done") && e.contains("38505:3956")),
            "{events:?}"
        );
    }

    #[test]
    fn append_sends_internaldate_between_flags_and_literal() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        ep.session = SessionState::Authenticated;
        let mut fake = FakeEp::new();

        ImapClientAuthenticated::append(
            &mut ep,
            "INBOX",
            Some("\\Seen"),
            Some("01-Jan-2024 00:00:00 +0000"),
            5,
            false,
        );
        ep.flush_outbound(&mut fake);
        let wire_out = fake.sent_str();
        assert!(
            wire_out.contains("(\\Seen) \"01-Jan-2024 00:00:00 +0000\" {5}"),
            "{wire_out:?}"
        );
    }

    #[test]
    fn mailbox_ops_round_trip() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        ep.session = SessionState::Authenticated;
        let mut fake = FakeEp::new();

        ImapClientAuthenticated::create(&mut ep, "Archive");
        ep.flush_outbound(&mut fake);
        assert!(fake.sent_str().contains("CREATE Archive"));
        feed(&mut ep, &mut fake, b"A000 OK CREATE completed\r\n");

        ImapClientAuthenticated::delete(&mut ep, "Old");
        ep.flush_outbound(&mut fake);
        assert!(fake.sent_str().contains("DELETE Old"));
        feed(&mut ep, &mut fake, b"A001 OK DELETE completed\r\n");

        ImapClientAuthenticated::rename(&mut ep, "Old", "New");
        ep.flush_outbound(&mut fake);
        assert!(fake.sent_str().contains("RENAME Old New"));
        feed(&mut ep, &mut fake, b"A002 OK RENAME completed\r\n");

        ImapClientAuthenticated::subscribe(&mut ep, "Archive");
        ep.flush_outbound(&mut fake);
        assert!(fake.sent_str().contains("SUBSCRIBE Archive"));
        feed(&mut ep, &mut fake, b"A003 OK SUBSCRIBE completed\r\n");

        ImapClientAuthenticated::unsubscribe(&mut ep, "Archive");
        ep.flush_outbound(&mut fake);
        assert!(fake.sent_str().contains("UNSUBSCRIBE Archive"));
        feed(&mut ep, &mut fake, b"A004 NO UNSUBSCRIBE failed\r\n");

        let events = log.lock().unwrap().clone();
        let ok_count = events.iter().filter(|e| *e == "mailbox_op_done:Ok").count();
        let no_count = events.iter().filter(|e| *e == "mailbox_op_done:No").count();
        assert_eq!(ok_count, 4, "{events:?}");
        assert_eq!(no_count, 1, "{events:?}");
    }

    #[test]
    fn enable_feature_tracking() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        ep.session = SessionState::Authenticated;
        ep.caps.enable = true;
        ep.caps.condstore = true;
        let mut fake = FakeEp::new();
        ImapClientAuthenticated::enable(&mut ep, "CONDSTORE");
        ep.flush_outbound(&mut fake);
        feed(
            &mut ep,
            &mut fake,
            b"* ENABLED CONDSTORE\r\nA000 OK ENABLE\r\n",
        );
        assert!(ep.enabled_features().condstore);
        let events = log.lock().unwrap().clone();
        assert!(
            events.iter().any(|e| e.contains("enabled:condstore=true")),
            "{events:?}"
        );
        assert!(
            events.iter().any(|e| e.starts_with("enable_done")),
            "{events:?}"
        );
    }

    #[test]
    fn unsolicited_during_pending_status() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        ep.session = SessionState::Selected;
        let mut fake = FakeEp::new();
        ImapClientAuthenticated::status(&mut ep, "INBOX", "MESSAGES");
        ep.flush_outbound(&mut fake);
        feed(
            &mut ep,
            &mut fake,
            b"* 9 EXISTS\r\n* STATUS INBOX (MESSAGES 2)\r\nA000 OK\r\n",
        );
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "exists:9"), "{events:?}");
        assert!(
            events.iter().any(|e| e == "status_data:INBOX:2"),
            "{events:?}"
        );
    }

    #[test]
    fn pipeline_status_and_list_helper() {
        use crate::client::pipeline_status_and_list;
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        ep.session = SessionState::Authenticated;
        let mut fake = FakeEp::new();
        pipeline_status_and_list(&mut ep, "INBOX", "MESSAGES", "", "*");
        assert_eq!(ep.pending_len(), 2);
        ep.flush_outbound(&mut fake);
        let out = fake.sent_str();
        let status_pos = out.find("STATUS").expect("STATUS issued");
        let list_pos = out.find("LIST").expect("LIST issued");
        assert!(
            status_pos < list_pos,
            "STATUS should be issued before LIST: {out}"
        );
    }

    #[test]
    fn timeout_cleanup_drains_pending() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        ep.session = SessionState::Authenticated;
        ImapClientAuthenticated::status(&mut ep, "INBOX", "MESSAGES");
        assert_eq!(ep.pending_len(), 1);
        let mut fake = FakeEp::new();
        let err = io::Error::new(io::ErrorKind::TimedOut, "IMAP command timed out");
        ProtocolHandler::error(&mut ep, &mut fake, &err);
        assert_eq!(ep.pending_len(), 0);
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "timeout"), "{events:?}");
        assert!(fake.closed);
    }

    #[test]
    fn disconnect_cleanup_during_idle() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut ep = make_ep(&log);
        ep.session = SessionState::Selected;
        let mut fake = FakeEp::new();
        ImapClientAuthenticated::idle(&mut ep);
        ep.flush_outbound(&mut fake);
        feed(&mut ep, &mut fake, b"+ idling\r\n");
        assert!(ep.is_idle_active());
        ProtocolHandler::disconnected(&mut ep, &mut fake);
        assert_eq!(ep.pending_len(), 0);
        let events = log.lock().unwrap().clone();
        assert!(events.iter().any(|e| e == "disconnected"), "{events:?}");
    }
}
