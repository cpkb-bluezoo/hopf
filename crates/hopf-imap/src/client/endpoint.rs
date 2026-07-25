// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `ImapClientEndpoint` — async IMAP client as a [`ProtocolHandler`].
//!
//! Correlates pipelined tagged replies via [`PendingMap`], routes untagged
//! lines by [`classify_untagged`] to the oldest compatible pending command,
//! and delivers unsolicited EXISTS / EXPUNGE / FLAGS to
//! [`MailboxEventListener`] (including during active IDLE).

use std::io;
use std::time::Duration;

use base64::Engine;
use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, SharedTlsConnector, TimerHandle};

use super::handlers::{ImapClientDriver, ImapClientHandlerFactory};
use super::pending::{
    classify_untagged, ImapTagGenerator, PendingCommand, PendingKind, PendingMap, UntaggedClass,
};
use super::reply::{ImapReplyLexer, ImapStatus, ImapWireEvent};
use super::state::{
    ImapCapabilities, ImapClientAppend, ImapClientAuthExchange, ImapClientAuthenticated,
    ImapClientIdle, ImapClientNotAuthenticated, ImapClientPostStarttls, ImapClientSelected,
    ImapCopyUid, ImapEnabledFeatures, ImapFetchData, ImapListEntry, ImapMailboxInfo,
    ImapNamespaceData, ImapQuotaData, ImapQuotaRootData, ImapStatusData,
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
    /// CAPABILITY tokens accumulated from untagged lines.
    capa_buf: Vec<String>,
    /// Simple FETCH body accumulator for the current body owner.
    fetch_accum: ImapFetchData,
    /// APPEND payload waiting for `+` (when not using LITERAL-).
    append_pending_data: Option<Vec<u8>>,
    /// When true, next APPEND data is flushed immediately after command (LITERAL-).
    append_literal_minus: bool,
    /// Last `issue_no_ep` failure (surfaced on next flush).
    pending_issue_error: Option<String>,
    /// Last COPYUID seen for MOVE/COPY completion.
    last_copyuid: Option<ImapCopyUid>,
    /// ENABLE tokens from untagged ENABLED this round.
    enable_buf: Vec<String>,
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
            capa_buf: Vec::new(),
            fetch_accum: ImapFetchData::default(),
            append_pending_data: None,
            append_literal_minus: false,
            pending_issue_error: None,
            last_copyuid: None,
            enable_buf: Vec::new(),
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

    fn dispatch(&mut self, event: ImapWireEvent, ep: &mut dyn Endpoint) {
        match event {
            ImapWireEvent::Untagged {
                status,
                response_code,
                text,
                raw,
            } => self.on_untagged(status, response_code, text, raw, ep),
            ImapWireEvent::Continuation { text } => self.on_continuation(text, ep),
            ImapWireEvent::Tagged {
                tag,
                status,
                response_code,
                message,
            } => self.on_tagged(tag, status, response_code, message, ep),
            ImapWireEvent::LiteralData(data) => self.on_literal_data(data, ep),
            ImapWireEvent::LiteralComplete => {
                self.cancel_message_timer();
                self.on_literal_complete();
            }
            ImapWireEvent::Residual(text) => self.on_residual(text, ep),
        }
    }

    fn on_untagged(
        &mut self,
        status: Option<ImapStatus>,
        response_code: Option<String>,
        text: String,
        raw: String,
        ep: &mut dyn Endpoint,
    ) {
        if self.session == SessionState::Connecting {
            self.cancel_greeting_timer();
            let head = raw.to_ascii_uppercase();
            if head.starts_with("BYE") {
                self.protocol_error(ep, format!("IMAP greeting BYE: {text}"));
                return;
            }
            let preauth = head.starts_with("PREAUTH");
            self.session = if preauth {
                SessionState::Authenticated
            } else {
                SessionState::NotAuthenticated
            };
            let mut driver = match self.driver.take() {
                Some(d) => d,
                None => return,
            };
            if preauth {
                driver.on_authenticated(self, ep);
            } else {
                driver.on_greeting(self, ep, &text, false);
            }
            self.driver = Some(driver);
            return;
        }

        let class = classify_untagged(&raw);

        // CAPABILITY always accumulates when present.
        if class == UntaggedClass::Capability {
            let rest = raw
                .get("CAPABILITY".len()..)
                .unwrap_or("")
                .trim_start_matches(|c: char| c == ' ' || c == '\t');
            self.capa_buf.clear();
            for t in rest.split_whitespace() {
                self.capa_buf.push(t.to_ascii_uppercase());
            }
            return;
        }

        // Prefer pending-command consumers by class (oldest compatible).
        match class {
            UntaggedClass::List => {
                if self.pending.oldest_compatible(class).is_some() {
                    if let Some(entry) = ImapListEntry::parse(&raw) {
                        if let Some(mut driver) = self.driver.take() {
                            driver.on_list_line(&raw);
                            driver.on_list_entry(&entry);
                            self.driver = Some(driver);
                        }
                    } else if let Some(mut driver) = self.driver.take() {
                        driver.on_list_line(&raw);
                        self.driver = Some(driver);
                    }
                    return;
                }
            }
            UntaggedClass::Status => {
                if self.pending.oldest_compatible(class).is_some() {
                    if let Some(mut driver) = self.driver.take() {
                        driver.on_status_line(&raw);
                        if let Some(data) = ImapStatusData::parse(&raw) {
                            driver.on_status_data(&data);
                        }
                        self.driver = Some(driver);
                    }
                    return;
                }
            }
            UntaggedClass::Search => {
                if self.pending.oldest_compatible(class).is_some() {
                    let nums = parse_search_numbers(&raw);
                    if let Some(mut driver) = self.driver.take() {
                        driver.on_search_numbers(&nums);
                        self.driver = Some(driver);
                    }
                    return;
                }
            }
            UntaggedClass::Fetch => {
                self.route_fetch_classified(&raw, ep);
                return;
            }
            UntaggedClass::Exists | UntaggedClass::Recent | UntaggedClass::FlagsList => {
                if self
                    .pending
                    .oldest_compatible(class)
                    .map(|c| matches!(c.kind, PendingKind::Select | PendingKind::Examine))
                    == Some(true)
                {
                    self.collect_select_untagged(&raw, response_code.as_deref(), status);
                    return;
                }
                if self.route_mailbox_event(&raw, ep) {
                    return;
                }
            }
            UntaggedClass::Expunge => {
                if self.pending.oldest_of_kind(PendingKind::Expunge).is_some() {
                    if let Some((n, _)) = parse_number_atom(&raw) {
                        if let Some(mut driver) = self.driver.take() {
                            driver.on_expunge_seq(n);
                            self.driver = Some(driver);
                        }
                    }
                    return;
                }
                if self.route_mailbox_event(&raw, ep) {
                    return;
                }
            }
            UntaggedClass::Enabled => {
                if self.pending.oldest_of_kind(PendingKind::Enable).is_some() {
                    let rest = raw
                        .get("ENABLED".len()..)
                        .unwrap_or("")
                        .trim_start_matches(|c: char| c == ' ' || c == '\t');
                    for t in rest.split_whitespace() {
                        self.enable_buf.push(t.to_ascii_uppercase());
                    }
                    let tokens: Vec<&str> = self.enable_buf.iter().map(|s| s.as_str()).collect();
                    self.enabled.enable(
                        &tokens,
                        self.caps.condstore || self.caps.enable,
                        self.caps.qresync || self.caps.enable,
                    );
                    let enabled = self.enabled.clone();
                    if let Some(mut driver) = self.driver.take() {
                        driver.on_enabled(&enabled);
                        self.driver = Some(driver);
                    }
                    return;
                }
            }
            UntaggedClass::Namespace => {
                if self
                    .pending
                    .oldest_of_kind(PendingKind::Namespace)
                    .is_some()
                {
                    if let Some(data) = ImapNamespaceData::parse(&raw) {
                        if let Some(mut driver) = self.driver.take() {
                            driver.on_namespace(&data);
                            self.driver = Some(driver);
                        }
                    }
                    return;
                }
            }
            UntaggedClass::Id => {
                if self.pending.oldest_of_kind(PendingKind::Id).is_some() {
                    let params = parse_id_params(&raw);
                    if let Some(mut driver) = self.driver.take() {
                        driver.on_id_params(&params);
                        self.driver = Some(driver);
                    }
                    return;
                }
            }
            UntaggedClass::Quota => {
                if self.pending.oldest_of_kind(PendingKind::Quota).is_some() {
                    if let Some(data) = ImapQuotaData::parse(&raw) {
                        if let Some(mut driver) = self.driver.take() {
                            driver.on_quota(&data);
                            self.driver = Some(driver);
                        }
                    }
                    return;
                }
            }
            UntaggedClass::QuotaRoot => {
                if self.pending.oldest_of_kind(PendingKind::Quota).is_some() {
                    if let Some(data) = ImapQuotaRootData::parse(&raw) {
                        if let Some(mut driver) = self.driver.take() {
                            driver.on_quota_root(&data);
                            self.driver = Some(driver);
                        }
                    }
                    return;
                }
            }
            UntaggedClass::Capability | UntaggedClass::MailboxEvent | UntaggedClass::Other => {}
        }

        // Unsolicited mailbox events (IDLE, FETCH interleave, NOOP, …).
        if self.route_mailbox_event(&raw, ep) {
            return;
        }

        // Untagged OK/NO response codes (e.g. during SELECT / COPYUID).
        if status.is_some() {
            if let Some(ref code) = response_code {
                if code.to_ascii_uppercase().starts_with("COPYUID ") {
                    self.last_copyuid = ImapCopyUid::parse(code);
                }
            }
            self.collect_select_untagged(&raw, response_code.as_deref(), status);
        }
    }

    fn route_fetch_classified(&mut self, raw: &str, ep: &mut dyn Endpoint) {
        let flags_only = is_flags_only_fetch(raw);
        if flags_only {
            // Prefer Store consumer, else Fetch, else mailbox event.
            if self.pending.oldest_of_kind(PendingKind::Store).is_some() {
                self.route_fetch_line(raw, ep);
                return;
            }
            if self.pending.oldest_of_kind(PendingKind::Fetch).is_some() {
                // Unsolicited FLAGS interleaved with FETCH → event listener.
                if self.route_mailbox_event(raw, ep) {
                    return;
                }
            }
            if self.route_mailbox_event(raw, ep) {
                return;
            }
            return;
        }
        if let Some(cmd) = self.pending.oldest_of_kind(PendingKind::Fetch) {
            let tag = cmd.tag.clone();
            self.pending.set_fetch_literal_owner(tag);
            self.route_fetch_line(raw, ep);
            return;
        }
        // No FETCH pending — treat as unsolicited flags update if possible.
        let _ = self.route_mailbox_event(raw, ep);
    }

    fn collect_select_untagged(
        &mut self,
        raw: &str,
        response_code: Option<&str>,
        _status: Option<ImapStatus>,
    ) {
        let upper = raw.to_ascii_uppercase();
        if upper.starts_with("FLAGS ") {
            self.select_info.flags = parse_flag_list(&raw[6..]);
        } else if let Some((n, kind)) = parse_number_atom(raw) {
            match kind.as_str() {
                "EXISTS" => self.select_info.exists = n,
                "RECENT" => self.select_info.recent = n,
                _ => {}
            }
        }
        if let Some(code) = response_code {
            let cu = code.to_ascii_uppercase();
            if let Some(v) = cu.strip_prefix("UIDVALIDITY ") {
                self.select_info.uid_validity = v.trim().parse().ok();
            } else if let Some(v) = cu.strip_prefix("UIDNEXT ") {
                self.select_info.uid_next = v.trim().parse().ok();
            } else if let Some(v) = cu.strip_prefix("UNSEEN ") {
                self.select_info.unseen = v.trim().parse().ok();
            } else if let Some(v) = cu.strip_prefix("HIGHESTMODSEQ ") {
                self.select_info.highest_modseq = v.trim().parse().ok();
            } else if cu.starts_with("PERMANENTFLAGS") {
                let rest = code
                    .get("PERMANENTFLAGS".len()..)
                    .unwrap_or("")
                    .trim_start();
                self.select_info.permanent_flags = parse_flag_list(rest);
            } else if cu == "READ-WRITE" {
                self.select_info.read_write = Some(true);
            } else if cu == "READ-ONLY" {
                self.select_info.read_write = Some(false);
            } else if cu.starts_with("COPYUID ") {
                self.last_copyuid = ImapCopyUid::parse(code);
            }
        }
    }

    fn route_mailbox_event(&mut self, raw: &str, ep: &mut dyn Endpoint) -> bool {
        let _ = ep;
        let mut handled = false;
        if let Some((n, kind)) = parse_number_atom(raw) {
            match kind.as_str() {
                "EXISTS" => {
                    if let Some(mut driver) = self.driver.take() {
                        if let Some(listener) = driver.mailbox_events() {
                            listener.on_exists(n);
                        }
                        self.driver = Some(driver);
                    }
                    handled = true;
                }
                "RECENT" => {
                    if let Some(mut driver) = self.driver.take() {
                        if let Some(listener) = driver.mailbox_events() {
                            listener.on_recent(n);
                        }
                        self.driver = Some(driver);
                    }
                    handled = true;
                }
                "EXPUNGE" => {
                    if let Some(mut driver) = self.driver.take() {
                        if let Some(listener) = driver.mailbox_events() {
                            listener.on_expunge(n);
                        }
                        self.driver = Some(driver);
                    }
                    handled = true;
                }
                _ => {}
            }
        }
        if !handled {
            if let Some((seq, flags)) = parse_flags_only_fetch(raw) {
                if let Some(mut driver) = self.driver.take() {
                    if let Some(listener) = driver.mailbox_events() {
                        listener.on_flags(seq, &flags);
                    }
                    self.driver = Some(driver);
                }
                handled = true;
            }
        }
        if handled && self.session == SessionState::IdleActive {
            if let Some(mut driver) = self.driver.take() {
                driver.on_idle_mailbox_event(self);
                self.driver = Some(driver);
            }
        }
        handled
    }

    fn route_fetch_line(&mut self, raw: &str, ep: &mut dyn Endpoint) {
        let has_literal = crate::client::reply::trailing_literal_size(raw).is_some();
        if has_literal {
            self.arm_message_timer(ep);
        }
        if let Some(seq) = parse_fetch_seq(raw) {
            self.fetch_accum = ImapFetchData {
                seq,
                ..ImapFetchData::default()
            };
            if let Some(flags) = extract_flags(raw) {
                self.fetch_accum.flags = flags;
            }
            if let Some(uid) = extract_atom_number(raw, "UID") {
                self.fetch_accum.uid = Some(uid);
            }
            if let Some(sz) = extract_atom_number(raw, "RFC822.SIZE") {
                self.fetch_accum.size = Some(sz as u64);
            }
            if let Some(ms) = extract_atom_number(raw, "MODSEQ") {
                self.fetch_accum.modseq = Some(ms as u64);
            }
        }
        if let Some(mut driver) = self.driver.take() {
            driver.on_fetch_line(raw);
            // When the line announces a trailing literal the body has not
            // arrived yet; deliver the complete ImapFetchData (body included)
            // on LiteralComplete instead of firing early with an empty body.
            if !has_literal {
                driver.on_fetch_data(&self.fetch_accum);
            }
            self.driver = Some(driver);
        }
    }

    fn on_residual(&mut self, text: String, ep: &mut dyn Endpoint) {
        let _ = ep;
        if self.pending.fetch_literal_owner().is_some()
            || self.pending.oldest_of_kind(PendingKind::Fetch).is_some()
        {
            if let Some(mut driver) = self.driver.take() {
                driver.on_fetch_line(&text);
                self.driver = Some(driver);
            }
        }
    }

    fn on_literal_data(&mut self, data: Vec<u8>, ep: &mut dyn Endpoint) {
        if self.pending.fetch_literal_owner().is_some()
            || self.pending.oldest_of_kind(PendingKind::Fetch).is_some()
        {
            self.arm_message_timer(ep);
            self.fetch_accum.body.extend_from_slice(&data);
            if let Some(mut driver) = self.driver.take() {
                driver.on_fetch_literal(&data);
                self.driver = Some(driver);
            }
        }
    }

    fn on_literal_complete(&mut self) {
        // A FETCH body literal finished: deliver the accumulated message
        // (seq/uid/flags from the announcing line plus the full body) once.
        if self.pending.fetch_literal_owner().is_some()
            || self.pending.oldest_of_kind(PendingKind::Fetch).is_some()
        {
            if !self.fetch_accum.body.is_empty() {
                if let Some(mut driver) = self.driver.take() {
                    driver.on_fetch_data(&self.fetch_accum);
                    self.driver = Some(driver);
                }
            }
            self.fetch_accum.body.clear();
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
            if code.to_ascii_uppercase().starts_with("COPYUID ") {
                self.last_copyuid = ImapCopyUid::parse(code);
            }
        }

        match cmd.kind {
            PendingKind::Capability => {
                let caps = if !self.capa_buf.is_empty() {
                    ImapCapabilities::parse(&self.capa_buf.join(" "))
                } else if let Some(ref code) = response_code {
                    if code.to_ascii_uppercase().starts_with("CAPABILITY ") {
                        ImapCapabilities::parse(&code["CAPABILITY ".len()..])
                    } else {
                        ImapCapabilities::default()
                    }
                } else {
                    ImapCapabilities::default()
                };
                self.capa_buf.clear();
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
                    let mut driver = match self.driver.take() {
                        Some(d) => d,
                        None => return,
                    };
                    driver.on_authenticated(self, ep);
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
                let mut driver = match self.driver.take() {
                    Some(d) => d,
                    None => return,
                };
                driver.on_append_complete(self, ep, status, &message);
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
                self.enable_buf.clear();
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
            let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
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
        let b64 = base64::engine::general_purpose::STANDARD.encode(response);
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

    fn append(&mut self, mailbox: &str, flags: Option<&str>, size: u64, use_literal_minus: bool) {
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
        self.enable_buf.clear();
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

fn is_fetch_line(raw: &str) -> bool {
    let mut parts = raw.splitn(3, ' ');
    let _n = parts.next();
    matches!(parts.next(), Some(w) if w.eq_ignore_ascii_case("FETCH"))
}

fn parse_fetch_seq(raw: &str) -> Option<u32> {
    let n = raw.split_whitespace().next()?;
    n.parse().ok()
}

fn parse_number_atom(raw: &str) -> Option<(u32, String)> {
    let mut parts = raw.split_whitespace();
    let n: u32 = parts.next()?.parse().ok()?;
    let kind = parts.next()?.to_ascii_uppercase();
    Some((n, kind))
}

fn parse_search_numbers(raw: &str) -> Vec<u32> {
    let rest = raw
        .strip_prefix("SEARCH")
        .or_else(|| raw.strip_prefix("search"))
        .unwrap_or(raw)
        .trim();
    rest.split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect()
}

fn parse_flag_list(s: &str) -> Vec<String> {
    let s = s.trim();
    let s = s
        .strip_prefix('(')
        .and_then(|x| x.strip_suffix(')'))
        .unwrap_or(s);
    s.split_whitespace().map(|f| f.to_string()).collect()
}

fn parse_flags_only_fetch(raw: &str) -> Option<(u32, Vec<String>)> {
    if !is_flags_only_fetch(raw) {
        return None;
    }
    let seq = parse_fetch_seq(raw)?;
    let flags = extract_flags(raw)?;
    Some((seq, flags))
}

fn is_flags_only_fetch(raw: &str) -> bool {
    if !is_fetch_line(raw) {
        return false;
    }
    let upper = raw.to_ascii_uppercase();
    if !upper.contains("FLAGS") {
        return false;
    }
    !(upper.contains("BODY") || upper.contains("RFC822") || upper.contains("ENVELOPE"))
}

fn extract_flags(raw: &str) -> Option<Vec<String>> {
    let upper = raw.to_ascii_uppercase();
    let idx = upper.find("FLAGS")?;
    let rest = &raw[idx + 5..];
    let rest = rest.trim_start();
    if !rest.starts_with('(') {
        return None;
    }
    let end = rest.find(')')?;
    Some(parse_flag_list(&rest[..=end]))
}

fn extract_atom_number(raw: &str, atom: &str) -> Option<u32> {
    let upper = raw.to_ascii_uppercase();
    let atom_u = atom.to_ascii_uppercase();
    let idx = upper.find(&atom_u)?;
    let rest = raw[idx + atom.len()..].trim_start();
    // Skip optional '(' for MODSEQ (modseq)
    let rest = rest.strip_prefix('(').unwrap_or(rest);
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

fn parse_id_params(raw: &str) -> Vec<(String, String)> {
    let rest = raw
        .strip_prefix("ID ")
        .or_else(|| raw.strip_prefix("id "))
        .unwrap_or(raw)
        .trim();
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
        ) {
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
        ) {
        }
        fn on_auth_failed(
            &mut self,
            _a: &mut dyn ImapClientNotAuthenticated,
            _e: &mut dyn Endpoint,
            _m: &str,
        ) {
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
        fn on_fetch_line(&mut self, line: &str) {
            self.events.lock().unwrap().push(format!("fetch:{line}"));
        }
        fn on_fetch_literal(&mut self, data: &[u8]) {
            self.events
                .lock()
                .unwrap()
                .push(format!("lit:{}", data.len()));
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
            _st: ImapStatus,
            _m: &str,
        ) {
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
            events.iter().any(|e| e.starts_with("fetch:")),
            "FETCH should hit body consumer: {events:?}"
        );
        assert!(
            events.iter().any(|e| e.starts_with("fetch_done")),
            "tagged OK should complete fetch: {events:?}"
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
