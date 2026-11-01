// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! FTP data-connection [`ProtocolHandler`]s (RETR / STOR / LIST).
//!
//! Both handlers share a [`TransferState`] via `Arc<Mutex<_>>` with the
//! [`super::handler::FtpControlHandler`]. Content is pushed straight through
//! to the caller-supplied receiver/handle as it arrives — [`TransferState`]
//! never assembles a whole transfer in memory.

use std::io;
use std::sync::{Arc, Mutex};

use hopf_core::{BindingId, ConnHandle, Endpoint, ProtocolHandler, Runtime, SecurityInfo};

use super::{FtpStorHandle, MessageReceiveCallback, StorCallback, StorReady, StouCallback};

// ---------------------------------------------------------------------------
// Shared transfer state
// ---------------------------------------------------------------------------

/// What a transfer delivers on completion.
pub(crate) enum TransferMode {
    /// RETR / LIST / NLST — content streamed directly to the receiver.
    Receive(Box<dyn MessageReceiveCallback>),
    /// STOR / APPE — content pushed by the caller through a [`FtpStorHandle`].
    Stor(StorCallback),
    /// STOU — as STOR, but the completion callback also gets the
    /// server-assigned filename.
    Stou(StouCallback),
}

/// Shared between a data handler and the control handler.
pub(crate) struct TransferState {
    mode: Option<TransferMode>,
    /// `true` once `MessageReceiveCallback::start_message` has fired.
    message_started: bool,
    /// Set by the data handler when the data channel closes.
    pub data_done: bool,
    /// Set by the control handler when the `226` reply is received.
    pub ctrl_done: bool,
    /// Set by the control handler once `125`/`150` arrives — the server is
    /// ready to receive data (STOR must not send before this).
    pub start_ok: bool,
    /// Data-connection handle stashed by a STOR handler that connected before
    /// the `150`; consumed by [`Self::try_arm`] once both halves are ready.
    pub data_conn: Option<ConnHandle>,
    /// STOR/APPE/STOU only: called exactly once, when the data connection is
    /// armed, with a handle the caller pushes content through.
    ready: Option<StorReady>,
    /// `STOU` only: the `125`/`150` reply text, holding the server-assigned
    /// filename (set by the control handler alongside `start_ok`).
    pub assigned_name: String,
    /// Set by the control handler on a `426` reply (RFC 959 §4.1.1 `ABOR`)
    /// — forces `maybe_complete` to report an error regardless of whatever
    /// the data-connection side otherwise observed, since a race between the
    /// two sides could otherwise let a partial/aborted transfer report as a
    /// silent success.
    aborted: bool,
    /// Set by the data handler's `error()` — takes precedence over a plain
    /// `Ok(())` completion, but not over `aborted`.
    data_error: Option<io::Error>,
}

impl TransferState {
    /// Create state for a RETR or LIST/NLST transfer.
    pub fn retr(receiver: Box<dyn MessageReceiveCallback>) -> Self {
        Self::new(TransferMode::Receive(receiver), None)
    }

    /// Create state for a STOR or APPE transfer.
    pub fn stor(ready: StorReady, cb: StorCallback) -> Self {
        Self::new(TransferMode::Stor(cb), Some(ready))
    }

    /// Create state for a STOU transfer.
    pub fn stou(ready: StorReady, cb: StouCallback) -> Self {
        Self::new(TransferMode::Stou(cb), Some(ready))
    }

    fn new(mode: TransferMode, ready: Option<StorReady>) -> Self {
        Self {
            mode: Some(mode),
            message_started: false,
            data_done: false,
            ctrl_done: false,
            start_ok: false,
            data_conn: None,
            ready,
            assigned_name: String::new(),
            aborted: false,
            data_error: None,
        }
    }

    /// Mark the control side done via an abort (`426`) rather than a normal
    /// `226`/`250` completion — `maybe_complete` will report an error even
    /// if the data side otherwise completed cleanly.
    pub fn mark_aborted(&mut self) {
        self.aborted = true;
        self.ctrl_done = true;
    }

    /// Feed one chunk of RETR/LIST/NLST content to the receiver. Returns
    /// `false` once the receiver asks to stop (the caller should then close
    /// the data connection).
    pub fn push_content(&mut self, chunk: &[u8]) -> bool {
        let Some(TransferMode::Receive(r)) = self.mode.as_mut() else {
            return true;
        };
        if !self.message_started {
            r.start_message();
            self.message_started = true;
        }
        r.message_content(chunk)
    }

    /// If both the data connection and the `125`/`150` reply have arrived,
    /// take the `ready` callback and the data handle for the caller to fire.
    pub fn try_arm(&mut self) -> Option<(StorReady, ConnHandle)> {
        if !self.start_ok {
            return None;
        }
        match (self.ready.take(), self.data_conn.take()) {
            (Some(ready), Some(conn)) => Some((ready, conn)),
            (ready, conn) => {
                // Not both present yet — put back whichever we took.
                self.ready = ready;
                self.data_conn = conn;
                None
            }
        }
    }

    /// Fire the completion callback once both data and control halves have
    /// completed.
    pub fn maybe_complete(&mut self) {
        if !self.data_done || !self.ctrl_done {
            return;
        }
        let mode = match self.mode.take() {
            Some(m) => m,
            None => return,
        };
        let result = if self.aborted {
            Err(io::Error::new(io::ErrorKind::Interrupted, "transfer aborted (ABOR)"))
        } else if let Some(e) = self.data_error.take() {
            Err(e)
        } else {
            Ok(())
        };
        match mode {
            TransferMode::Receive(mut r) => {
                if !self.message_started {
                    r.start_message();
                }
                r.end_message(result);
            }
            TransferMode::Stor(cb) => cb(result),
            TransferMode::Stou(cb) => {
                let name = std::mem::take(&mut self.assigned_name);
                cb(result.map(|_| name))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RETR / LIST data handler
// ---------------------------------------------------------------------------

/// Forwards server-sent bytes from a passive data connection straight to the
/// transfer's [`MessageReceiveCallback`].
pub(crate) struct FtpDataRetrHandler {
    transfer: Arc<Mutex<TransferState>>,
}

impl FtpDataRetrHandler {
    pub fn new(transfer: Arc<Mutex<TransferState>>) -> Self {
        Self { transfer }
    }
}

impl ProtocolHandler for FtpDataRetrHandler {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            let keep_going = self.transfer.lock().unwrap().push_content(data);
            *data = &[];
            if !keep_going {
                endpoint.close();
            }
        });
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        let mut g = self.transfer.lock().unwrap();
        g.data_done = true;
        g.maybe_complete();
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
        let mut g = self.transfer.lock().unwrap();
        g.data_error = Some(io::Error::new(err.kind(), err.to_string()));
        g.data_done = true;
        g.maybe_complete();
    }
}

// ---------------------------------------------------------------------------
// STOR data handler
// ---------------------------------------------------------------------------

/// Arms a data connection for upload and, once both it and the server's
/// `125`/`150` are ready, hands the caller a [`FtpStorHandle`] to push
/// content through.
pub(crate) struct FtpDataStorHandler {
    transfer: Arc<Mutex<TransferState>>,
    /// When true (active-mode TLS-from-accept), wait for
    /// [`ProtocolHandler::security_established`] before arming so content
    /// is not pushed before the handshake completes.
    expect_tls: bool,
    armed: bool,
}

impl FtpDataStorHandler {
    /// Plaintext or outbound-TLS dial — arm as soon as TCP is up.
    pub fn new(transfer: Arc<Mutex<TransferState>>) -> Self {
        Self {
            transfer,
            expect_tls: false,
            armed: false,
        }
    }

    /// TLS-from-accept (active mode + `PROT P`) — arm after handshake.
    pub fn new_expect_tls(transfer: Arc<Mutex<TransferState>>) -> Self {
        Self {
            transfer,
            expect_tls: true,
            armed: false,
        }
    }

    fn arm(&mut self, endpoint: &mut dyn Endpoint) {
        if self.armed {
            return;
        }
        self.armed = true;
        let mut g = self.transfer.lock().unwrap();
        g.data_conn = Some(endpoint.handle());
        let armed = g.try_arm();
        drop(g);
        if let Some((ready, conn)) = armed {
            ready(FtpStorHandle::new(conn));
        }
    }
}

impl ProtocolHandler for FtpDataStorHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if !self.expect_tls {
            self.arm(endpoint);
        }
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {
        if self.expect_tls {
            self.arm(endpoint);
        }
    }

    fn receive(&mut self, _endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            *data = &[]; // server sends nothing on the data channel for STOR
        });
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        let mut g = self.transfer.lock().unwrap();
        g.data_done = true;
        g.maybe_complete();
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &io::Error) {
        let mut g = self.transfer.lock().unwrap();
        g.data_error = Some(io::Error::new(err.kind(), err.to_string()));
        g.data_done = true;
        g.maybe_complete();
    }
}

/// Wraps a data handler so the one-shot active-mode listen binding is
/// removed as soon as the server connects (or the socket errors out).
pub(crate) struct ActiveAcceptGuard {
    rt: Arc<Runtime>,
    binding: BindingId,
    removed: bool,
    inner: Box<dyn ProtocolHandler>,
}

impl ActiveAcceptGuard {
    pub fn new(rt: Arc<Runtime>, binding: BindingId, inner: Box<dyn ProtocolHandler>) -> Self {
        Self {
            rt,
            binding,
            removed: false,
            inner,
        }
    }

    fn drop_binding(&mut self) {
        if !self.removed {
            self.rt.remove_binding(self.binding);
            self.removed = true;
        }
    }
}

impl ProtocolHandler for ActiveAcceptGuard {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        self.drop_binding();
        self.inner.connected(endpoint);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            hopf_core::forward_slice(&mut *self.inner, endpoint, data);
        });
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        self.drop_binding();
        self.inner.disconnected(endpoint);
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, info: &SecurityInfo) {
        self.inner.security_established(endpoint, info);
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error) {
        self.drop_binding();
        self.inner.error(endpoint, err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct CollectReceiver {
        collected: Arc<Mutex<Vec<u8>>>,
        started: Arc<AtomicBool>,
        result: Arc<Mutex<Option<io::Result<()>>>>,
    }

    impl MessageReceiveCallback for CollectReceiver {
        fn start_message(&mut self) {
            self.started.store(true, Ordering::SeqCst);
        }
        fn message_content(&mut self, chunk: &[u8]) -> bool {
            self.collected.lock().unwrap().extend_from_slice(chunk);
            true
        }
        fn end_message(&mut self, result: io::Result<()>) {
            *self.result.lock().unwrap() = Some(result);
        }
    }

    #[test]
    fn abort_reports_error_even_with_data_already_done() {
        // Simulates the data side finishing (or already having finished)
        // with an apparent success *before* the control side's 426 (ABOR)
        // arrives — the callback must still see an error, not the data
        // side's success.
        let result = Arc::new(Mutex::new(None));
        let receiver = CollectReceiver {
            collected: Arc::new(Mutex::new(Vec::new())),
            started: Arc::new(AtomicBool::new(false)),
            result: Arc::clone(&result),
        };
        let mut state = TransferState::retr(Box::new(receiver));

        // Data side completes first, reporting apparent success.
        state.push_content(b"partial-bytes-received-before-abort");
        state.data_done = true;
        state.maybe_complete(); // ctrl_done still false — must not fire yet.
        assert!(result.lock().unwrap().is_none());

        // Control side's 426 arrives.
        state.mark_aborted();
        state.maybe_complete();
        let r = result.lock().unwrap().take().expect("callback should have fired");
        assert!(r.is_err(), "aborted transfer should report an error");
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn abort_before_data_side_also_reports_error() {
        let fired = Arc::new(AtomicBool::new(false));
        let fired2 = Arc::clone(&fired);
        let mut state = TransferState::stor(
            Box::new(|_handle| {}),
            Box::new(move |res| {
                assert!(res.is_err());
                fired2.store(true, Ordering::SeqCst);
            }),
        );

        // Control side's 426 arrives before the data connection closes.
        state.mark_aborted();
        state.maybe_complete(); // data_done still false — must not fire yet.
        assert!(!fired.load(Ordering::SeqCst));

        state.data_done = true;
        state.maybe_complete();
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn normal_completion_unaffected() {
        let result = Arc::new(Mutex::new(None));
        let collected = Arc::new(Mutex::new(Vec::new()));
        let receiver = CollectReceiver {
            collected: Arc::clone(&collected),
            started: Arc::new(AtomicBool::new(false)),
            result: Arc::clone(&result),
        };
        let mut state = TransferState::retr(Box::new(receiver));
        state.push_content(b"hello");
        state.data_done = true;
        state.ctrl_done = true;
        state.maybe_complete();
        assert!(result.lock().unwrap().take().unwrap().is_ok());
        assert_eq!(&*collected.lock().unwrap(), b"hello");
    }

    #[test]
    fn stop_signal_from_receiver_is_honored() {
        struct StopAfterOne(usize);
        impl MessageReceiveCallback for StopAfterOne {
            fn message_content(&mut self, _chunk: &[u8]) -> bool {
                self.0 += 1;
                self.0 < 1
            }
            fn end_message(&mut self, _result: io::Result<()>) {}
        }
        let mut state = TransferState::retr(Box::new(StopAfterOne(0)));
        assert!(!state.push_content(b"first"));
    }

    use hopf_core::testing::Peer;

    type Seen = Arc<Mutex<(Vec<String>, Option<io::Result<()>>)>>;

    /// Records every callback, in order, as text.
    struct Recorder {
        seen: Seen,
        keep_going: bool,
    }

    impl MessageReceiveCallback for Recorder {
        fn start_message(&mut self) {
            self.seen.lock().unwrap().0.push("start".into());
        }
        fn message_content(&mut self, chunk: &[u8]) -> bool {
            let text = String::from_utf8_lossy(chunk).into_owned();
            self.seen.lock().unwrap().0.push(text);
            self.keep_going
        }
        fn end_message(&mut self, result: io::Result<()>) {
            let mut g = self.seen.lock().unwrap();
            g.0.push("end".into());
            g.1 = Some(result);
        }
    }

    fn download(keep_going: bool) -> (Peer<FtpDataRetrHandler>, Arc<Mutex<TransferState>>, Seen) {
        let seen = Seen::default();
        let state = Arc::new(Mutex::new(TransferState::retr(Box::new(Recorder {
            seen: Arc::clone(&seen),
            keep_going,
        }))));
        let peer = Peer::connect(FtpDataRetrHandler::new(Arc::clone(&state)), |_| false);
        (peer, state, seen)
    }

    #[test]
    fn download_content_arrives_as_it_is_read() {
        let (mut peer, _state, seen) = download(true);
        peer.run("abc");
        peer.run("def");
        assert_eq!(seen.lock().unwrap().0, ["start", "abc", "def"]);
    }

    #[test]
    fn download_ends_only_when_both_channels_are_done() {
        let (mut peer, state, seen) = download(true);
        peer.run("data");
        peer.disconnect();
        assert!(seen.lock().unwrap().1.is_none(), "control side has not said 226 yet");
        {
            let mut g = state.lock().unwrap();
            g.ctrl_done = true;
            g.maybe_complete();
        }
        let g = seen.lock().unwrap();
        assert_eq!(g.0, ["start", "data", "end"]);
        assert!(g.1.as_ref().unwrap().is_ok());
    }

    #[test]
    fn download_whose_226_came_first_ends_when_the_data_closes() {
        let (mut peer, state, seen) = download(true);
        peer.run("data");
        state.lock().unwrap().ctrl_done = true;
        assert!(seen.lock().unwrap().1.is_none());
        peer.disconnect();
        assert_eq!(seen.lock().unwrap().0, ["start", "data", "end"]);
    }

    #[test]
    fn an_empty_download_still_starts_and_ends_the_message() {
        let (mut peer, state, seen) = download(true);
        state.lock().unwrap().ctrl_done = true;
        peer.disconnect();
        assert_eq!(seen.lock().unwrap().0, ["start", "end"]);
    }

    #[test]
    fn a_receiver_that_stops_closes_the_data_connection() {
        let (mut peer, _state, seen) = download(false);
        peer.run("first");
        assert!(peer.is_closed());
        assert_eq!(seen.lock().unwrap().0, ["start", "first"]);
    }

    #[test]
    fn a_data_error_is_reported_as_the_transfers_result() {
        let (mut peer, state, seen) = download(true);
        peer.run("part");
        state.lock().unwrap().ctrl_done = true;
        let err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        peer.fail(&err);
        let g = seen.lock().unwrap();
        assert_eq!(g.0, ["start", "part", "end"]);
        assert_eq!(g.1.as_ref().unwrap().as_ref().unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    }

    #[test]
    fn an_abort_wins_over_a_data_error() {
        let (mut peer, state, seen) = download(true);
        state.lock().unwrap().mark_aborted();
        let err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        peer.fail(&err);
        let g = seen.lock().unwrap();
        assert_eq!(g.1.as_ref().unwrap().as_ref().unwrap_err().kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn the_completion_callback_fires_once() {
        let (mut peer, state, seen) = download(true);
        {
            let mut g = state.lock().unwrap();
            g.ctrl_done = true;
        }
        peer.disconnect();
        state.lock().unwrap().maybe_complete();
        let ends = seen.lock().unwrap().0.iter().filter(|e| *e == "end").count();
        assert_eq!(ends, 1);
    }

    #[test]
    fn an_upload_is_armed_only_once_the_server_has_said_150() {
        let armed = Arc::new(AtomicBool::new(false));
        let armed2 = Arc::clone(&armed);
        let state = Arc::new(Mutex::new(TransferState::stor(
            Box::new(move |_handle| armed2.store(true, Ordering::SeqCst)),
            Box::new(|_| {}),
        )));
        let mut peer = Peer::connect(FtpDataStorHandler::new(Arc::clone(&state)), |_| false);
        assert!(!armed.load(Ordering::SeqCst), "the 150 has not arrived");
        assert!(state.lock().unwrap().data_conn.is_some());

        state.lock().unwrap().start_ok = true;
        let ready = state.lock().unwrap().try_arm();
        let (ready, conn) = ready.expect("both halves are present");
        ready(FtpStorHandle::new(conn));
        assert!(armed.load(Ordering::SeqCst));
        // Whatever the server sends on an upload's data channel is dropped.
        peer.run("ignored");
    }

    #[test]
    fn an_upload_whose_150_came_first_is_armed_when_the_data_connects() {
        let armed = Arc::new(AtomicBool::new(false));
        let armed2 = Arc::clone(&armed);
        let state = Arc::new(Mutex::new(TransferState::stor(
            Box::new(move |_handle| armed2.store(true, Ordering::SeqCst)),
            Box::new(|_| {}),
        )));
        state.lock().unwrap().start_ok = true;
        let _peer = Peer::connect(FtpDataStorHandler::new(Arc::clone(&state)), |_| false);
        assert!(armed.load(Ordering::SeqCst));
    }

    #[test]
    fn a_tls_upload_waits_for_the_handshake() {
        let armed = Arc::new(AtomicBool::new(false));
        let armed2 = Arc::clone(&armed);
        let state = Arc::new(Mutex::new(TransferState::stor(
            Box::new(move |_handle| armed2.store(true, Ordering::SeqCst)),
            Box::new(|_| {}),
        )));
        state.lock().unwrap().start_ok = true;
        let _peer = Peer::connect(FtpDataStorHandler::new_expect_tls(Arc::clone(&state)), |_| false);
        assert!(!armed.load(Ordering::SeqCst), "no content before the handshake");
        assert!(state.lock().unwrap().data_conn.is_none());
    }

    #[test]
    fn stou_reports_the_name_the_server_assigned() {
        let name = Arc::new(Mutex::new(None));
        let name2 = Arc::clone(&name);
        let mut state = TransferState::stou(
            Box::new(|_handle| {}),
            Box::new(move |r| *name2.lock().unwrap() = Some(r)),
        );
        state.assigned_name = "unique-7".into();
        state.data_done = true;
        state.ctrl_done = true;
        state.maybe_complete();
        assert_eq!(name.lock().unwrap().take().unwrap().unwrap(), "unique-7");
    }
}
