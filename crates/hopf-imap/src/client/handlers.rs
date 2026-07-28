// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP client handler factory, driver, and mailbox event listener.

use std::io;

use hopf_core::Endpoint;

use super::reply::ImapStatus;
use super::state::{
    ImapCapabilities, ImapClientAppend, ImapClientAuthExchange, ImapClientAuthenticated,
    ImapClientIdle, ImapClientNotAuthenticated, ImapClientPostStarttls, ImapClientSelected,
    ImapCopyUid, ImapEnabledFeatures, ImapFetchData, ImapListEntry, ImapMailboxInfo,
    ImapNamespaceData, ImapQuotaData, ImapQuotaRootData, ImapStatusData,
};

/// Creates the connection driver for each new IMAP client connection.
pub trait ImapClientHandlerFactory: Send + Sync {
    /// Produce a fresh driver for one connection.
    fn create(&self) -> Box<dyn ImapClientDriver>;
}

/// Unsolicited mailbox events (EXISTS / EXPUNGE / FLAGS) when no matching
/// body consumer owns the line — including during active IDLE.
pub trait MailboxEventListener: Send {
    /// `* n EXISTS`
    fn on_exists(&mut self, count: u32);
    /// `* n RECENT`
    fn on_recent(&mut self, count: u32);
    /// `* n EXPUNGE`
    fn on_expunge(&mut self, seq: u32);
    /// `* n FETCH (FLAGS (…))` unsolicited flag update
    fn on_flags(&mut self, seq: u32, flags: &[String]);
}

/// No-op mailbox event listener.
#[derive(Debug, Default)]
pub struct NopMailboxEventListener;

impl MailboxEventListener for NopMailboxEventListener {
    fn on_exists(&mut self, _count: u32) {}
    fn on_recent(&mut self, _count: u32) {}
    fn on_expunge(&mut self, _seq: u32) {}
    fn on_flags(&mut self, _seq: u32, _flags: &[String]) {}
}

/// Consolidated IMAP client driver (Hopf SMTP/POP3 style).
///
/// Drive the session by calling methods on the staged state references.
/// Default method bodies are no-ops so custom drivers only override what they
/// need; command-completion still flows through dedicated hooks when present.
pub trait ImapClientDriver: Send {
    /// Optional mailbox event listener for unsolicited EXISTS/EXPUNGE/FLAGS.
    fn mailbox_events(&mut self) -> Option<&mut dyn MailboxEventListener> {
        None
    }

    /// Server greeting (`* OK` / `* PREAUTH` / `* BYE`).
    fn on_greeting(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        text: &str,
        preauth: bool,
    );

    /// CAPABILITY response (pre- or post-auth).
    fn on_capability(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        caps: &ImapCapabilities,
    );

    /// TLS handshake completed after STARTTLS; must re-issue CAPABILITY.
    fn on_tls_established(&mut self, post: &mut dyn ImapClientPostStarttls, ep: &mut dyn Endpoint);

    /// STARTTLS rejected or unavailable.
    fn on_tls_unavailable(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        message: &str,
    );

    /// LOGIN / AUTHENTICATE succeeded.
    fn on_authenticated(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
    );

    /// LOGIN / AUTHENTICATE failed (NO/BAD).
    fn on_auth_failed(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        message: &str,
    );

    /// AUTHENTICATE continuation (`+`).
    fn on_auth_continue(
        &mut self,
        exchange: &mut dyn ImapClientAuthExchange,
        ep: &mut dyn Endpoint,
        text: &str,
    );

    /// SELECT / EXAMINE completed.
    fn on_selected(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        ep: &mut dyn Endpoint,
        info: &ImapMailboxInfo,
        read_only: bool,
    );

    /// SELECT / EXAMINE failed.
    fn on_select_failed(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
        message: &str,
    );

    /// FETCH literal octets.
    fn on_fetch_literal(&mut self, data: &[u8]);

    /// Parsed FETCH attributes when a simple FETCH line is recognised.
    fn on_fetch_data(&mut self, data: &ImapFetchData) {
        let _ = data;
    }

    /// FETCH command completed (tagged OK/NO/BAD).
    fn on_fetch_complete(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        message: &str,
    );

    /// Untagged SEARCH numbers.
    fn on_search_numbers(&mut self, numbers: &[u32]) {
        let _ = numbers;
    }

    /// SEARCH completed.
    fn on_search_complete(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        message: &str,
    ) {
        let _ = (selected, ep, status, message);
    }

    /// Parsed LIST / LSUB entry.
    fn on_list_entry(&mut self, entry: &ImapListEntry) {
        let _ = entry;
    }

    /// LIST completed.
    fn on_list_complete(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        message: &str,
    ) {
        let _ = (session, ep, status, message);
    }

    /// Parsed STATUS data.
    fn on_status_data(&mut self, data: &ImapStatusData) {
        let _ = data;
    }

    /// STATUS completed.
    fn on_status_complete(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        message: &str,
    ) {
        let _ = (session, ep, status, message);
    }

    /// STORE / UID STORE completed (FETCH flag updates may precede this).
    fn on_store_complete(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        message: &str,
    ) {
        let _ = (selected, ep, status, message);
    }

    /// COPY / UID COPY completed.
    fn on_copy_complete(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        copyuid: Option<&ImapCopyUid>,
        message: &str,
    ) {
        let _ = (selected, ep, status, copyuid, message);
    }

    /// MOVE / UID MOVE completed.
    fn on_move_complete(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        copyuid: Option<&ImapCopyUid>,
        message: &str,
    ) {
        let _ = (selected, ep, status, copyuid, message);
    }

    /// One EXPUNGE sequence during an EXPUNGE / UID EXPUNGE command.
    fn on_expunge_seq(&mut self, seq: u32) {
        let _ = seq;
    }

    /// EXPUNGE / UID EXPUNGE completed.
    fn on_expunge_complete(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        message: &str,
    ) {
        let _ = (selected, ep, status, message);
    }

    /// Untagged `ENABLED` features (also tracked on the session).
    fn on_enabled(&mut self, features: &ImapEnabledFeatures) {
        let _ = features;
    }

    /// ENABLE completed.
    fn on_enable_complete(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        enabled: &ImapEnabledFeatures,
        message: &str,
    ) {
        let _ = (session, ep, status, enabled, message);
    }

    /// NAMESPACE data.
    fn on_namespace(&mut self, data: &ImapNamespaceData) {
        let _ = data;
    }

    /// NAMESPACE completed.
    fn on_namespace_complete(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        message: &str,
    ) {
        let _ = (session, ep, status, message);
    }

    /// Server `ID` parameter list as `key/value` pairs (`NIL` → empty).
    fn on_id_params(&mut self, params: &[(String, String)]) {
        let _ = params;
    }

    /// ID completed.
    fn on_id_complete(&mut self, ep: &mut dyn Endpoint, status: ImapStatus, message: &str) {
        let _ = (ep, status, message);
    }

    /// Untagged QUOTA.
    fn on_quota(&mut self, data: &ImapQuotaData) {
        let _ = data;
    }

    /// Untagged QUOTAROOT.
    fn on_quota_root(&mut self, data: &ImapQuotaRootData) {
        let _ = data;
    }

    /// Quota command completed.
    fn on_quota_complete(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        message: &str,
    ) {
        let _ = (session, ep, status, message);
    }

    /// IDLE continuation received — session is now actively idling.
    fn on_idle_started(&mut self, idle: &mut dyn ImapClientIdle, ep: &mut dyn Endpoint) {
        let _ = (idle, ep);
    }

    /// Called after an unsolicited mailbox event while IDLE is active.
    ///
    /// Default pipelines may use this to send [`ImapClientIdle::done`].
    fn on_idle_mailbox_event(&mut self, idle: &mut dyn ImapClientIdle) {
        let _ = idle;
    }

    /// IDLE tagged completion after `DONE` (or server BYE/NO).
    fn on_idle_complete(
        &mut self,
        session: &mut dyn ImapClientSelected,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        message: &str,
    ) {
        let _ = (session, ep, status, message);
    }

    /// CLOSE / UNSELECT completed; session returns to AUTHENTICATED.
    fn on_deselect_complete(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        message: &str,
    ) {
        let _ = (session, ep, status, message);
    }

    /// APPEND continuation — send literal via `append.send_literal`.
    fn on_append_continue(
        &mut self,
        append: &mut dyn ImapClientAppend,
        ep: &mut dyn Endpoint,
        text: &str,
    );

    /// APPEND completed.
    fn on_append_complete(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        message: &str,
    );

    /// Generic tagged completion for commands without a dedicated callback.
    fn on_command_complete(
        &mut self,
        ep: &mut dyn Endpoint,
        tag: &str,
        status: ImapStatus,
        response_code: Option<&str>,
        message: &str,
    ) {
        let _ = (ep, tag, status, response_code, message);
    }

    /// Unrecoverable I/O or protocol error.
    fn on_error(&mut self, ep: &mut dyn Endpoint, err: &io::Error);

    /// Stage / connect / message timeout.
    fn on_timeout(&mut self, ep: &mut dyn Endpoint);

    /// Connection closed.
    fn on_disconnected(&mut self, ep: &mut dyn Endpoint);
}
