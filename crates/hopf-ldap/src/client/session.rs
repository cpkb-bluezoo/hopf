// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared session state and [`LdapSession`] handle.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, SharedTlsConnector};

use super::message::{
    encode_bind_request, encode_search_request, encode_starttls_request, encode_unbind_request,
};
use super::types::{BindResult, LdapError, SearchDone, SearchEntry, SearchRequest};

pub(crate) type BindCallback = Box<dyn FnOnce(Result<BindResult, LdapError>) + Send>;
pub(crate) type SearchEntryCallback = Box<dyn FnMut(SearchEntry) + Send>;
pub(crate) type SearchDoneCallback = Box<dyn FnOnce(Result<SearchDone, LdapError>) + Send>;
pub(crate) type StartTlsCallback = Box<dyn FnOnce(Result<(), LdapError>) + Send>;
pub(crate) type ReadyCallback = Box<dyn FnOnce(Result<LdapSession, LdapError>) + Send>;

pub(crate) enum PendingOp {
    Bind(BindCallback),
    Search {
        on_entry: SearchEntryCallback,
        on_done: SearchDoneCallback,
        referrals: Vec<String>,
    },
    StartTls(StartTlsCallback),
}

/// Shared state between the reactor [`super::endpoint::LdapEndpoint`] and
/// off-reactor [`LdapSession`] handle.
pub(crate) struct LdapShared {
    pub(crate) conn: Mutex<Option<ConnHandle>>,
    pub(crate) next_message_id: AtomicI32,
    pub(crate) pending: Mutex<HashMap<i32, PendingOp>>,
    pub(crate) closed: AtomicBool,
    pub(crate) ready_delivered: AtomicBool,
    /// STARTTLS connector + SNI (plaintext dials only).
    pub(crate) starttls: Option<(SharedTlsConnector, String)>,
}

impl LdapShared {
    pub(crate) fn new(starttls: Option<(SharedTlsConnector, String)>) -> Self {
        Self {
            conn: Mutex::new(None),
            next_message_id: AtomicI32::new(1),
            pending: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            ready_delivered: AtomicBool::new(false),
            starttls,
        }
    }

    pub(crate) fn alloc_message_id(&self) -> i32 {
        self.next_message_id.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn send_bytes(&self, data: Vec<u8>) -> Result<(), LdapError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(LdapError::Closed);
        }
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(LdapError::Closed)?;
        conn.send(data);
        Ok(())
    }

    pub(crate) fn fail_all_pending(&self, err: LdapError) {
        let pending: HashMap<i32, PendingOp> = std::mem::take(
            &mut *self
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        let mut first = Some(err);
        for (_, op) in pending {
            let e = first.take().unwrap_or(LdapError::Closed);
            match op {
                PendingOp::Bind(cb) => cb(Err(e)),
                PendingOp::Search { on_done, .. } => on_done(Err(e)),
                PendingOp::StartTls(cb) => cb(Err(e)),
            }
        }
    }

    pub(crate) fn mark_closed(&self) {
        self.closed.store(true, Ordering::Release);
        if let Some(conn) = self
            .conn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            conn.close();
        }
    }
}

/// Handle for LDAP operations on an established connection.
///
/// Methods encode BER and send via [`ConnHandle`]; responses are dispatched
/// on the reactor thread into the supplied callbacks. Callbacks must not
/// perform long blocking work on the reactor — signal a worker instead.
#[derive(Clone)]
pub struct LdapSession {
    pub(crate) shared: Arc<LdapShared>,
}

impl LdapSession {
    /// Whether STARTTLS material was configured on this dial.
    pub fn starttls_configured(&self) -> bool {
        self.shared.starttls.is_some()
    }

    /// STARTTLS extended operation then TLS upgrade (RFC 4511 §4.14).
    ///
    /// Requires [`LdapClientConfig::with_starttls`](super::LdapClientConfig::with_starttls).
    /// On success the callback runs after `security_established` (TLS handshake done).
    pub fn start_tls<F>(&self, callback: F)
    where
        F: FnOnce(Result<(), LdapError>) + Send + 'static,
    {
        if self.shared.starttls.is_none() {
            callback(Err(LdapError::Config(
                "STARTTLS not configured on this session".into(),
            )));
            return;
        }
        let message_id = self.shared.alloc_message_id();
        self.shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(message_id, PendingOp::StartTls(Box::new(callback)));
        let bytes = encode_starttls_request(message_id);
        if let Err(e) = self.shared.send_bytes(bytes) {
            if let Some(PendingOp::StartTls(cb)) = self
                .shared
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&message_id)
            {
                cb(Err(e));
            }
        }
    }

    /// Simple bind (RFC 4511 §4.2 / RFC 4513 §5.1).
    pub fn bind<F>(&self, dn: &str, password: &str, callback: F)
    where
        F: FnOnce(Result<BindResult, LdapError>) + Send + 'static,
    {
        let dn = dn.to_owned();
        let password = password.to_owned();
        let message_id = self.shared.alloc_message_id();
        self.shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(message_id, PendingOp::Bind(Box::new(callback)));
        let bytes = encode_bind_request(message_id, &dn, &password);
        if let Err(e) = self.shared.send_bytes(bytes) {
            if let Some(PendingOp::Bind(cb)) = self
                .shared
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&message_id)
            {
                cb(Err(e));
            }
        }
    }

    /// Anonymous bind (empty DN and password).
    pub fn bind_anonymous<F>(&self, callback: F)
    where
        F: FnOnce(Result<BindResult, LdapError>) + Send + 'static,
    {
        self.bind("", "", callback);
    }

    /// Search (RFC 4511 §4.5). `on_entry` is invoked for each
    /// SearchResultEntry; `on_done` once for SearchResultDone (includes
    /// collected referral URLs from references / referral result).
    pub fn search<E, D>(&self, request: SearchRequest, on_entry: E, on_done: D)
    where
        E: FnMut(SearchEntry) + Send + 'static,
        D: FnOnce(Result<SearchDone, LdapError>) + Send + 'static,
    {
        let message_id = self.shared.alloc_message_id();
        self.shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                message_id,
                PendingOp::Search {
                    on_entry: Box::new(on_entry),
                    on_done: Box::new(on_done),
                    referrals: Vec::new(),
                },
            );
        let bytes = encode_search_request(message_id, &request);
        if let Err(e) = self.shared.send_bytes(bytes) {
            if let Some(PendingOp::Search { on_done, .. }) = self
                .shared
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&message_id)
            {
                on_done(Err(e));
            }
        }
    }

    /// Unbind and close the connection (RFC 4511 §4.3). No response expected.
    pub fn unbind(&self) {
        if self.shared.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let message_id = self.shared.alloc_message_id();
        let bytes = encode_unbind_request(message_id);
        let _ = self.shared.send_bytes(bytes);
        if let Some(conn) = self
            .shared
            .conn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            conn.close();
        }
        self.shared.fail_all_pending(LdapError::Closed);
    }

    /// Whether the session has been closed / unbound.
    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }
}
