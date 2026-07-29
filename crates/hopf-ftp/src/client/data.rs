// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP data-connection [`ProtocolHandler`]s (RETR / STOR / LIST).
//!
//! Both handlers share a [`TransferState`] via `Arc<Mutex<_>>` with the
//! [`super::handler::FtpControlHandler`]. Whichever side completes last
//! fires the user callback.

use std::io;
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler};

use super::{RetrCallback, StorCallback, StouCallback};

// ---------------------------------------------------------------------------
// Shared transfer state
// ---------------------------------------------------------------------------

/// Callback delivered when a passive data transfer completes.
pub(crate) enum TransferCallback {
    Retr(RetrCallback),
    Stor(StorCallback),
    /// `STOU` — delivers the server-assigned filename (from the `125`/`150`
    /// reply text) alongside the outcome.
    Stou(StouCallback),
}

/// Shared between a data handler and the control handler.
pub(crate) struct TransferState {
    /// Data collected by the data handler; `None` until the data channel
    /// closes (or errors).
    pub data: Option<io::Result<Vec<u8>>>,
    /// Set by the data handler when the data channel closes.
    pub data_done: bool,
    /// Set by the control handler when the `226` reply is received.
    pub ctrl_done: bool,
    /// Set by the control handler once `125`/`150` arrives — the server is
    /// ready to receive data (STOR must not send before this).
    pub start_ok: bool,
    /// Data-connection handle stashed by a STOR handler that connected before
    /// the `150`; the control handler triggers the upload through it.
    pub data_conn: Option<ConnHandle>,
    /// STOR payload paired with `data_conn`.
    pub stor_payload: Option<Arc<Vec<u8>>>,
    /// `STOU` only: the `125`/`150` reply text, holding the server-assigned
    /// filename (set by the control handler alongside `start_ok`).
    pub assigned_name: String,
    /// Set by the control handler on a `426` reply (RFC 959 §4.1.1 `ABOR`)
    /// — forces `maybe_complete` to report an error regardless of whatever
    /// partial data the data-connection side collected, since a race
    /// between the two sides could otherwise let a partial/aborted
    /// transfer report as a silent success.
    aborted: bool,
    /// User callback — consumed exactly once when both sides are done.
    callback: Option<TransferCallback>,
}

impl TransferState {
    /// Create state for a RETR or LIST/NLST transfer.
    pub fn retr(cb: RetrCallback) -> Self {
        Self {
            data: None,
            data_done: false,
            ctrl_done: false,
            start_ok: false,
            data_conn: None,
            stor_payload: None,
            assigned_name: String::new(),
            aborted: false,
            callback: Some(TransferCallback::Retr(cb)),
        }
    }

    /// Create state for a STOR or APPE transfer.
    pub fn stor(cb: StorCallback) -> Self {
        Self {
            data: None,
            data_done: false,
            ctrl_done: false,
            start_ok: false,
            data_conn: None,
            stor_payload: None,
            assigned_name: String::new(),
            aborted: false,
            callback: Some(TransferCallback::Stor(cb)),
        }
    }

    /// Create state for a STOU transfer.
    pub fn stou(cb: StouCallback) -> Self {
        Self {
            data: None,
            data_done: false,
            ctrl_done: false,
            start_ok: false,
            data_conn: None,
            stor_payload: None,
            assigned_name: String::new(),
            aborted: false,
            callback: Some(TransferCallback::Stou(cb)),
        }
    }

    /// Mark the control side done via an abort (`426`) rather than a normal
    /// `226`/`250` completion — `maybe_complete` will report an error even
    /// if the data side already collected (or later collects) bytes.
    pub fn mark_aborted(&mut self) {
        self.aborted = true;
        self.ctrl_done = true;
    }

    /// Fire the callback once both data and control halves have completed.
    pub fn maybe_complete(&mut self) {
        if !self.data_done || !self.ctrl_done {
            return;
        }
        let cb = match self.callback.take() {
            Some(c) => c,
            None => return,
        };
        let result = if self.aborted {
            Err(io::Error::new(io::ErrorKind::Interrupted, "transfer aborted (ABOR)"))
        } else {
            self.data.take().unwrap_or(Ok(Vec::new()))
        };
        match cb {
            TransferCallback::Retr(f) => f(result),
            TransferCallback::Stor(f) => f(result.map(|_| ())),
            TransferCallback::Stou(f) => {
                let name = std::mem::take(&mut self.assigned_name);
                f(result.map(|_| name))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RETR / LIST data handler
// ---------------------------------------------------------------------------

/// Accumulates server-sent bytes from a passive data connection.
pub(crate) struct FtpDataRetrHandler {
    buf: Vec<u8>,
    transfer: Arc<Mutex<TransferState>>,
}

impl FtpDataRetrHandler {
    pub fn new(transfer: Arc<Mutex<TransferState>>) -> Self {
        Self {
            buf: Vec::new(),
            transfer,
        }
    }
}

impl ProtocolHandler for FtpDataRetrHandler {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.buf.extend_from_slice(data);
        *data = &[];
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        let data = std::mem::take(&mut self.buf);
        let mut g = self.transfer.lock().unwrap();
        g.data = Some(Ok(data));
        g.data_done = true;
        g.maybe_complete();
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
        let mut g = self.transfer.lock().unwrap();
        g.data = Some(Err(io::Error::new(err.kind(), err.to_string())));
        g.data_done = true;
        g.maybe_complete();
    }
}

// ---------------------------------------------------------------------------
// STOR data handler
// ---------------------------------------------------------------------------

/// Sends a buffer over a passive data connection and signals completion.
pub(crate) struct FtpDataStorHandler {
    /// Use `Arc` so the factory closure can clone cheaply without copying data.
    data: Arc<Vec<u8>>,
    transfer: Arc<Mutex<TransferState>>,
}

impl FtpDataStorHandler {
    pub fn new(data: Arc<Vec<u8>>, transfer: Arc<Mutex<TransferState>>) -> Self {
        Self { data, transfer }
    }
}

impl ProtocolHandler for FtpDataStorHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        let mut g = self.transfer.lock().unwrap();
        if g.start_ok {
            // Server already said 125/150 — upload immediately.
            drop(g);
            endpoint.send(&self.data);
            endpoint.close(); // graceful half-close after sending
        } else {
            // Wait for the control channel's 150 before sending; stash a
            // handle so the control handler can trigger the upload.
            g.data_conn = Some(endpoint.handle());
            g.stor_payload = Some(Arc::clone(&self.data));
        }
    }

    fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        *data = &[]; // server sends nothing on the data channel for STOR
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        let mut g = self.transfer.lock().unwrap();
        g.data = Some(Ok(Vec::new()));
        g.data_done = true;
        g.maybe_complete();
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
        let mut g = self.transfer.lock().unwrap();
        g.data = Some(Err(io::Error::new(err.kind(), err.to_string())));
        g.data_done = true;
        g.maybe_complete();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn abort_reports_error_even_with_data_already_done() {
        // Simulates the data side finishing (or already having finished)
        // with an apparent success *before* the control side's 426 (ABOR)
        // arrives — the callback must still see an error, not the data
        // side's success.
        let fired = Arc::new(AtomicBool::new(false));
        let fired2 = Arc::clone(&fired);
        let mut state = TransferState::retr(Box::new(move |res| {
            assert!(res.is_err(), "aborted transfer should report an error");
            assert_eq!(res.unwrap_err().kind(), io::ErrorKind::Interrupted);
            fired2.store(true, Ordering::SeqCst);
        }));

        // Data side completes first, reporting apparent success.
        state.data = Some(Ok(b"partial-bytes-received-before-abort".to_vec()));
        state.data_done = true;
        state.maybe_complete(); // ctrl_done still false — must not fire yet.
        assert!(!fired.load(Ordering::SeqCst));

        // Control side's 426 arrives.
        state.mark_aborted();
        state.maybe_complete();
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn abort_before_data_side_also_reports_error() {
        let fired = Arc::new(AtomicBool::new(false));
        let fired2 = Arc::clone(&fired);
        let mut state = TransferState::stor(Box::new(move |res| {
            assert!(res.is_err());
            fired2.store(true, Ordering::SeqCst);
        }));

        // Control side's 426 arrives before the data connection closes.
        state.mark_aborted();
        state.maybe_complete(); // data_done still false — must not fire yet.
        assert!(!fired.load(Ordering::SeqCst));

        state.data = Some(Ok(Vec::new()));
        state.data_done = true;
        state.maybe_complete();
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn normal_completion_unaffected() {
        let fired = Arc::new(AtomicBool::new(false));
        let fired2 = Arc::clone(&fired);
        let mut state = TransferState::retr(Box::new(move |res| {
            assert_eq!(res.unwrap(), b"hello");
            fired2.store(true, Ordering::SeqCst);
        }));
        state.data = Some(Ok(b"hello".to_vec()));
        state.data_done = true;
        state.ctrl_done = true;
        state.maybe_complete();
        assert!(fired.load(Ordering::SeqCst));
    }
}
