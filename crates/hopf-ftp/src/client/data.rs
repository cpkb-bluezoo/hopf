// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP data-connection [`ProtocolHandler`]s (RETR / STOR / LIST).
//!
//! Both handlers share a [`TransferState`] via `Arc<Mutex<_>>` with the
//! [`super::handler::FtpControlHandler`]. Whichever side completes last
//! fires the user callback.

use std::io;
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler};

use super::{RetrCallback, StorCallback};

// ---------------------------------------------------------------------------
// Shared transfer state
// ---------------------------------------------------------------------------

/// Callback delivered when a passive data transfer completes.
pub(crate) enum TransferCallback {
    Retr(RetrCallback),
    Stor(StorCallback),
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
    /// User callback — consumed exactly once when both sides are done.
    callback: Option<TransferCallback>,
}

impl TransferState {
    /// Create state for a RETR or LIST transfer.
    pub fn retr(cb: RetrCallback) -> Self {
        Self {
            data: None,
            data_done: false,
            ctrl_done: false,
            start_ok: false,
            data_conn: None,
            stor_payload: None,
            callback: Some(TransferCallback::Retr(cb)),
        }
    }

    /// Create state for a STOR transfer.
    pub fn stor(cb: StorCallback) -> Self {
        Self {
            data: None,
            data_done: false,
            ctrl_done: false,
            start_ok: false,
            data_conn: None,
            stor_payload: None,
            callback: Some(TransferCallback::Stor(cb)),
        }
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
        let result = self.data.take().unwrap_or(Ok(Vec::new()));
        match cb {
            TransferCallback::Retr(f) => f(result),
            TransferCallback::Stor(f) => f(result.map(|_| ())),
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
