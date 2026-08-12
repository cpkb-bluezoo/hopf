// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Data-connection bridge and handler (PASV accept / active dial).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, StorageError, StorageExecutor};
use hopf_otel::{RequestTimer, Span, FtpServerMetrics as OtelFtpMetrics};

use crate::server::ascii::{AsciiNewlineDenormalizer, AsciiNewlineNormalizer};
use crate::server::handler::TransferObserver;
use crate::server::metrics::FtpServerMetrics;
use crate::server::reply::reply;

/// Bounded read chunk size for streamed RETR transfers.
const RETR_CHUNK_SIZE: usize = 8192;

/// OTel timing/span for one data transfer; finished from the data plane.
pub struct TransferTelemetry {
    timer: RequestTimer,
    span: Option<Span>,
    otel: Option<Arc<OtelFtpMetrics>>,
    direction: &'static str,
}

impl TransferTelemetry {
    /// Build for a transfer that has just been queued on the control connection.
    pub fn start(
        direction: &'static str,
        otel: Option<Arc<OtelFtpMetrics>>,
        span: Option<Span>,
    ) -> Self {
        Self {
            timer: RequestTimer::start(),
            span,
            otel,
            direction,
        }
    }

    /// Record duration / size and end the span.
    pub fn finish(self, ok: bool, bytes: u64) {
        let outcome = if ok { "ok" } else { "fail" };
        if let Some(span) = self.span {
            span.set_attribute("ftp.transfer.direction", self.direction);
            span.set_attribute("outcome", outcome);
            if ok {
                span.set_status_ok();
            } else {
                span.set_status_error(outcome);
            }
            span.end();
        }
        if let Some(m) = &self.otel {
            m.transfer_completed(self.direction, outcome, self.timer.elapsed(), bytes);
        }
    }
}

/// Outbound (server→client) transfer.
pub enum OutboundTransfer {
    /// RETR file body.
    Retr {
        /// TYPE A.
        ascii: bool,
        /// Reader.
        reader: Box<dyn Read + Send>,
        /// NVFS path (for the transfer observer).
        path: String,
        /// Progress/completion observer, if the app wants one.
        observer: Option<Arc<dyn TransferObserver>>,
        /// Optional OTel transfer instrumentation.
        telemetry: Option<TransferTelemetry>,
    },
    /// Preformatted listing.
    Listing {
        /// Bytes.
        body: Vec<u8>,
        /// Optional OTel transfer instrumentation.
        telemetry: Option<TransferTelemetry>,
    },
}

/// Everything the data connection needs to drive one STOR/APPE/STOU upload.
pub struct StorTransfer {
    /// TYPE A — denormalize network CRLF to local LF while writing.
    pub ascii: bool,
    /// NVFS path (for the transfer observer / quota accounting).
    pub path: String,
    /// Writer to stream bytes into.
    pub writer: Box<dyn Write + Send>,
    /// Progress/completion observer, if the app wants one.
    pub observer: Option<Arc<dyn TransferObserver>>,
    /// Quota manager + username to record usage against, once the upload
    /// completes successfully.
    pub quota: Option<(Arc<dyn hopf_core::QuotaManager>, String)>,
    /// Optional OTel transfer instrumentation.
    pub telemetry: Option<TransferTelemetry>,
}

/// Shared state between control and one data connection.
pub struct DataBridge {
    inner: Mutex<DataBridgeState>,
}

struct DataBridgeState {
    data_handle: Option<ConnHandle>,
    control_handle: Option<ConnHandle>,
    outbound: Option<OutboundTransfer>,
    stor: Option<StorTransfer>,
    /// Set by [`DataBridge::abort`]; completion paths skip control replies.
    aborted: bool,
    metrics: Arc<FtpServerMetrics>,
    storage: Arc<StorageExecutor>,
}

impl DataBridge {
    /// Create an empty bridge.
    pub fn new(storage: Arc<StorageExecutor>, metrics: Arc<FtpServerMetrics>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(DataBridgeState {
                data_handle: None,
                control_handle: None,
                outbound: None,
                stor: None,
                aborted: false,
                metrics,
                storage,
                },
            ),
        })
    }

    /// Bind the control ConnHandle (for 226 replies after transfer).
    pub fn set_control(&self, handle: ConnHandle) {
        self.inner.lock().unwrap().control_handle = Some(handle);
    }

    /// Storage pool this bridge's transfers offload to — also used by
    /// [`FtpDataHandler`] to offload STOR upload writes (issue #224).
    pub fn storage(&self) -> Arc<StorageExecutor> {
        Arc::clone(&self.inner.lock().unwrap().storage)
    }

    /// Queue RETR / LIST; starts when the data peer is connected.
    pub fn queue_outbound(self: &Arc<Self>, transfer: OutboundTransfer) {
        {
            let mut g = self.inner.lock().unwrap();
            g.aborted = false;
            g.outbound = Some(transfer);
        }
        self.try_start_outbound();
    }

    /// Queue a STOR / APPE / STOU upload for the data handler.
    pub fn queue_stor(&self, transfer: StorTransfer) {
        let mut g = self.inner.lock().unwrap();
        g.aborted = false;
        g.stor = Some(transfer);
    }

    /// Whether [`Self::abort`] has been called for the current transfer.
    pub fn was_aborted(&self) -> bool {
        self.inner.lock().unwrap().aborted
    }

    /// Cancel any queued/in-flight transfer and close the data connection.
    ///
    /// Returns `true` if a transfer was in progress (RFC 959: reply 426 then
    /// 226). Completion callbacks skip their own control replies after this.
    pub fn abort(&self) -> bool {
        let (in_progress, handle) = {
            let mut g = self.inner.lock().unwrap();
            let in_progress =
                g.outbound.is_some() || g.stor.is_some() || g.data_handle.is_some();
            g.aborted = true;
            g.outbound = None;
            g.stor = None;
            (in_progress, g.data_handle.take())
        };
        if let Some(h) = handle {
            h.close();
        }
        in_progress
    }

    /// Data peer connected.
    pub fn on_data_connected(self: &Arc<Self>, handle: ConnHandle) {
        self.inner.lock().unwrap().data_handle = Some(handle);
        self.try_start_outbound();
    }

    /// Take the queued STOR transfer (data handler, at arm time).
    pub fn take_stor_transfer(&self) -> Option<StorTransfer> {
        self.inner.lock().unwrap().stor.take()
    }

    /// Data peer closed.
    pub fn on_data_closed(&self) {
        self.inner.lock().unwrap().data_handle = None;
    }

    /// Finish STOR successfully.
    pub fn stor_complete(&self, bytes: u64) {
        let g = self.inner.lock().unwrap();
        if g.aborted {
            return;
        }
        FtpServerMetrics::add(&g.metrics.bytes_in, bytes);
        if let Some(c) = &g.control_handle {
            c.send(reply(226, "Transfer complete"));
        }
    }

    /// Finish STOR with error.
    pub fn stor_failed(&self) {
        let g = self.inner.lock().unwrap();
        if g.aborted {
            return;
        }
        if let Some(c) = &g.control_handle {
            c.send(reply(426, "Transfer aborted"));
        }
    }

    fn send_transfer_reply(control: &Option<ConnHandle>, aborted: bool, ok: bool) {
        if aborted {
            return;
        }
        if let Some(c) = control {
            if ok {
                c.send(reply(226, "Transfer complete"));
            } else {
                c.send(reply(426, "Transfer aborted"));
            }
        }
    }

    fn try_start_outbound(self: &Arc<Self>) {
        let (transfer, data, control, storage, metrics) = {
            let mut g = self.inner.lock().unwrap();
            let transfer = match g.outbound.take() {
                Some(t) => t,
                None => return,
            };
            let data = match g.data_handle.clone() {
                Some(h) => h,
                None => {
                    g.outbound = Some(transfer);
                    return;
                }
            };
            (
                transfer,
                data,
                g.control_handle.clone(),
                Arc::clone(&g.storage),
                Arc::clone(&g.metrics),
            )
        };
        let bridge = Arc::clone(self);
        let bridge_done = Arc::clone(self);

        match transfer {
            OutboundTransfer::Retr {
                ascii,
                mut reader,
                path,
                observer,
                telemetry,
            } => {
                let progress_observer = observer.clone();
                let progress_path = path.clone();
                let complete_observer = observer;
                let complete_path = path;
                storage.submit_streamed(
                    data.clone(),
                    move |conn: &ConnHandle| {
                        let mut buf = vec![0u8; RETR_CHUNK_SIZE];
                        let mut norm = AsciiNewlineNormalizer::new();
                        let mut total = 0u64;
                        loop {
                            if !conn.is_probably_open() {
                                // Distinguishing ABOR from clean EOF: treat a
                                // mid-stream close as failure so we don't claim
                                // success after abort (completion still checks
                                // `was_aborted` before any control reply).
                                if bridge.was_aborted() {
                                    return Err("transfer aborted".into());
                                }
                                break;
                            }
                            let n = reader.read(&mut buf)?;
                            if n == 0 {
                                break;
                            }
                            if ascii {
                                let mut out = Vec::with_capacity(n + 16);
                                norm.feed(&buf[..n], &mut out);
                                total += out.len() as u64;
                                if !out.is_empty() {
                                    if let Some(obs) = &progress_observer {
                                        obs.transfer_progress(&progress_path, false, &out, total);
                                    }
                                    conn.send(out);
                                }
                            } else {
                                total += n as u64;
                                if let Some(obs) = &progress_observer {
                                    obs.transfer_progress(&progress_path, false, &buf[..n], total);
                                }
                                conn.send(buf[..n].to_vec());
                            }
                        }
                        if ascii {
                            let mut tail = Vec::new();
                            norm.finish(&mut tail);
                            if !tail.is_empty() {
                                total += tail.len() as u64;
                                if let Some(obs) = &progress_observer {
                                    obs.transfer_progress(&progress_path, false, &tail, total);
                                }
                                conn.send(tail);
                            }
                        }
                        if bridge.was_aborted() {
                            return Err("transfer aborted".into());
                        }
                        Ok::<u64, Box<dyn std::error::Error + Send + Sync>>(total)
                    },
                    move |result| {
                        let aborted = bridge_done.was_aborted();
                        let (ok, n) = match result {
                            Ok(n) => {
                                FtpServerMetrics::add(&metrics.bytes_out, n);
                                if let Some(obs) = &complete_observer {
                                    obs.transfer_completed(&complete_path, false, n, true);
                                }
                                data.close();
                                Self::send_transfer_reply(&control, aborted, true);
                                (!aborted, n)
                            }
                            Err(_) => {
                                if let Some(obs) = &complete_observer {
                                    obs.transfer_completed(&complete_path, false, 0, false);
                                }
                                data.close();
                                Self::send_transfer_reply(&control, aborted, false);
                                (false, 0)
                            }
                        };
                        if let Some(t) = telemetry {
                            t.finish(ok, n);
                        }
                    },
                );
            }
            OutboundTransfer::Listing { body, telemetry } => {
                if bridge.was_aborted() {
                    if let Some(t) = telemetry {
                        t.finish(false, 0);
                    }
                    data.close();
                    return;
                }
                let n = body.len() as u64;
                FtpServerMetrics::add(&metrics.bytes_out, n);
                data.send(body);
                data.close();
                let ok = !bridge.was_aborted();
                if let Some(t) = telemetry {
                    t.finish(ok, n);
                }
                Self::send_transfer_reply(&control, bridge.was_aborted(), true);
            }
        }
    }
}

/// Ordered, offloaded write queue for one STOR/APPE/STOU upload (issue
/// #224) — `FtpDataHandler::receive` only ever enqueues; the actual
/// `Write::write_all` calls run on the storage pool, one chunk at a time,
/// in submission order (writes to the same writer must land in order;
/// `StorageExecutor::submit_on` gives no cross-call ordering guarantee on
/// its own) — mirrors `hopf_mqtt::server::publish_spool`'s
/// `SpoolWriteState`/`drain_next_publish_chunk`.
struct StorWriteState {
    writer: Option<Box<dyn Write + Send>>,
    /// NVFS path / observer, duplicated from `FtpDataHandler` so the
    /// storage-pool completion callback (which only ever gets a cloned
    /// `Arc`, never `&FtpDataHandler`) can report per-chunk progress once
    /// each chunk's write has actually landed, not just been received.
    path: String,
    observer: Option<Arc<dyn TransferObserver>>,
    queue: VecDeque<Vec<u8>>,
    /// One write in flight at a time — set while a chunk is submitted to
    /// the storage pool, cleared once its callback lands and the queue is
    /// empty.
    draining: bool,
    /// Set once a write fails — remaining queued chunks are dropped
    /// rather than written after a gap.
    error: bool,
    bytes_written: u64,
    /// Set by [`finish_stor_when_drained`] when the queue isn't already
    /// empty at that point — run once, right here on the storage thread,
    /// the moment the queue actually empties. Carries `(bytes_written,
    /// had_error)` for the caller to decide success/failure.
    on_drained: Option<Box<dyn FnOnce(u64, bool) + Send>>,
}

/// Queue `chunk` for `state`, kicking off the drain if nothing else is
/// already in flight. A no-op once `state` has latched an error, or for
/// an empty chunk (nothing to write).
fn enqueue_stor_chunk(state: &Arc<Mutex<StorWriteState>>, storage: &Arc<StorageExecutor>, handle: &ConnHandle, chunk: Vec<u8>) {
    if chunk.is_empty() {
        return;
    }
    let mut g = state.lock().unwrap();
    if g.error {
        return;
    }
    g.queue.push_back(chunk);
    let should_start = !g.draining;
    if should_start {
        g.draining = true;
    }
    drop(g);
    if should_start {
        drain_next_stor_chunk(Arc::clone(state), Arc::clone(storage), handle.clone());
    }
}

/// Drain the next queued chunk (if any) by submitting its write to the
/// storage pool; on completion, either drains the next one, or — once the
/// queue is empty — runs `on_drained` if [`finish_stor_when_drained`] set
/// one while writes were still in flight. Free function (not a method)
/// since it needs to re-invoke itself from inside a `'static` storage
/// callback, which only has cloned `Arc`s/a `ConnHandle`.
fn drain_next_stor_chunk(state: Arc<Mutex<StorWriteState>>, storage: Arc<StorageExecutor>, handle: ConnHandle) {
    let chunk = {
        let mut g = state.lock().unwrap();
        if g.error {
            g.queue.clear();
            g.draining = false;
            if let Some(cb) = g.on_drained.take() {
                let bytes = g.bytes_written;
                drop(g);
                cb(bytes, true);
            }
            return;
        }
        match g.queue.pop_front() {
            Some(c) => c,
            None => {
                g.draining = false;
                if let Some(cb) = g.on_drained.take() {
                    let bytes = g.bytes_written;
                    drop(g);
                    cb(bytes, false);
                }
                return;
            }
        }
    };
    let op_state = Arc::clone(&state);
    let cb_state = Arc::clone(&state);
    let cb_storage = Arc::clone(&storage);
    let cb_handle = handle.clone();
    storage.submit_on(
        handle,
        move || -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            let mut g = op_state.lock().unwrap();
            let w = g.writer.as_mut().ok_or("writer already closed")?;
            w.write_all(&chunk)?;
            // Flushed after every chunk (not just the last) — simpler than
            // a separate final flush job, and correct for any writer
            // (buffered or not): `std::fs::File::flush` is a no-op, so
            // this costs nothing for the common case.
            w.flush()?;
            Ok(chunk)
        },
        move |result: Result<Vec<u8>, StorageError>| {
            match result {
                Ok(chunk) => {
                    let mut g = cb_state.lock().unwrap();
                    g.bytes_written += chunk.len() as u64;
                    if let Some(obs) = &g.observer {
                        obs.transfer_progress(&g.path, true, &chunk, g.bytes_written);
                    }
                }
                Err(_) => {
                    let mut g = cb_state.lock().unwrap();
                    g.error = true;
                    g.writer = None;
                }
            }
            drain_next_stor_chunk(cb_state, cb_storage, cb_handle);
        },
    );
}

/// Run `on_finished(bytes_written, had_error)` once every queued write for
/// `state` has landed — immediately, inline, if nothing is currently
/// draining; otherwise deferred until the last chunk's completion callback
/// picks it up. Mirrors `hopf_mqtt::server::publish_spool::PendingPublish::finish_when_ready`.
fn finish_stor_when_drained(state: Arc<Mutex<StorWriteState>>, on_finished: Box<dyn FnOnce(u64, bool) + Send>) {
    let mut g = state.lock().unwrap();
    if !g.draining && g.queue.is_empty() {
        let bytes = g.bytes_written;
        let had_error = g.error;
        drop(g);
        on_finished(bytes, had_error);
        return;
    }
    g.on_drained = Some(on_finished);
}

/// Protocol handler for one data connection.
pub struct FtpDataHandler {
    bridge: Arc<DataBridge>,
    /// When true, wait for [`ProtocolHandler::security_established`] before arming.
    expect_tls: bool,
    /// The only peer address this data connection may actually come
    /// from/go to — the control connection's remote IP for PASV/EPSV, or
    /// the PORT/EPRT-supplied dial target for active mode (already
    /// verified against the control peer unless `allow_active_bounce`).
    /// Checked again here, independent of transport, so a PASV listener
    /// never hands transfer data to a third party that merely guessed or
    /// observed the ephemeral port.
    expected_peer: IpAddr,
    armed: bool,
    /// This connection's own `ConnHandle`, captured at [`Self::arm`] time —
    /// used (issue #224) to dispatch offloaded STOR chunk writes to the
    /// storage pool. Always `Some` once `receive`/`disconnected` can run
    /// (the reactor only calls them after `connected`/`security_established`,
    /// which always call `arm`).
    data_handle: Option<ConnHandle>,
    storage: Arc<StorageExecutor>,
    stor_state: Option<Arc<Mutex<StorWriteState>>>,
    stor_path: String,
    stor_observer: Option<Arc<dyn TransferObserver>>,
    stor_quota: Option<(Arc<dyn hopf_core::QuotaManager>, String)>,
    stor_ascii: bool,
    stor_denorm: AsciiNewlineDenormalizer,
    stor_telemetry: Option<TransferTelemetry>,
}

impl FtpDataHandler {
    /// Create for an accepted/dialed data socket.
    pub fn new(bridge: Arc<DataBridge>, expect_tls: bool, expected_peer: IpAddr) -> Self {
        let storage = bridge.storage();
        Self {
            bridge,
            expect_tls,
            expected_peer,
            armed: false,
            data_handle: None,
            storage,
            stor_state: None,
            stor_path: String::new(),
            stor_observer: None,
            stor_quota: None,
            stor_ascii: false,
            stor_denorm: AsciiNewlineDenormalizer::new(),
            stor_telemetry: None,
        }
    }

    /// Pull in a queued [`StorTransfer`], if one is waiting and we haven't
    /// already got one — the data connection can arm (or start receiving,
    /// for active mode) before the control connection has actually queued
    /// the transfer, so both [`Self::arm`] and
    /// [`ProtocolHandler::receive`](ProtocolHandler) retry this.
    fn take_stor(&mut self) {
        if self.stor_state.is_none() {
            if let Some(t) = self.bridge.take_stor_transfer() {
                self.stor_path = t.path.clone();
                self.stor_observer = t.observer.clone();
                self.stor_quota = t.quota;
                self.stor_ascii = t.ascii;
                self.stor_denorm = AsciiNewlineDenormalizer::new();
                self.stor_telemetry = t.telemetry;
                self.stor_state = Some(Arc::new(Mutex::new(StorWriteState {
                    writer: Some(t.writer),
                    path: t.path,
                    observer: t.observer,
                    queue: VecDeque::new(),
                    draining: false,
                    error: false,
                    bytes_written: 0,
                    on_drained: None,
                })));
            }
        }
    }

    fn arm(&mut self, endpoint: &mut dyn Endpoint) {
        if self.armed {
            return;
        }
        match endpoint.remote_addr() {
            Ok(peer) if peer.ip() == self.expected_peer => {}
            _ => {
                // Wrong peer (or unknown) — never wire this connection
                // into the transfer, and drop it outright.
                endpoint.close();
                return;
            }
        }
        self.armed = true;
        let handle = endpoint.handle();
        self.data_handle = Some(handle.clone());
        self.bridge.on_data_connected(handle);
        self.take_stor();
    }
}

impl ProtocolHandler for FtpDataHandler {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if !self.expect_tls {
            self.arm(endpoint);
        }
    }

    fn security_established(
        &mut self,
        endpoint: &mut dyn Endpoint,
        _info: &hopf_core::SecurityInfo,
    ) {
        if self.expect_tls {
            self.arm(endpoint);
        }
    }

    fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.take_stor();
        if let Some(state) = &self.stor_state {
            let handle = self.data_handle.clone().expect("receive() only runs after arm()");
            if self.stor_ascii {
                let mut out = Vec::with_capacity(data.len());
                self.stor_denorm.feed(data, &mut out);
                enqueue_stor_chunk(state, &self.storage, &handle, out);
            } else {
                enqueue_stor_chunk(state, &self.storage, &handle, data.to_vec());
            }
        }
        *data = &[];
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        let Some(state) = self.stor_state.take() else {
            self.bridge.on_data_closed();
            return;
        };
        if self.stor_ascii {
            let mut tail = Vec::new();
            self.stor_denorm.finish(&mut tail);
            if !tail.is_empty() {
                let handle = self.data_handle.clone().expect("disconnected() only runs after arm()");
                enqueue_stor_chunk(&state, &self.storage, &handle, tail);
            }
        }
        let bridge = Arc::clone(&self.bridge);
        let observer = self.stor_observer.clone();
        let path = self.stor_path.clone();
        let quota = self.stor_quota.clone();
        let telemetry = self.stor_telemetry.take();
        finish_stor_when_drained(
            state,
            Box::new(move |bytes_written, had_error| {
                let aborted = bridge.was_aborted();
                let ok = !had_error && !aborted;
                if let Some(obs) = &observer {
                    obs.transfer_completed(&path, true, bytes_written, ok);
                }
                if ok {
                    if let Some((qm, user)) = &quota {
                        qm.record_bytes_added(user, bytes_written);
                    }
                    bridge.stor_complete(bytes_written);
                } else if had_error {
                    bridge.stor_failed();
                }
                if let Some(t) = telemetry {
                    t.finish(ok, bytes_written);
                }
                bridge.on_data_closed();
            }),
        );
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &std::io::Error) {
        if let Some(state) = self.stor_state.take() {
            let bytes_written = {
                let mut g = state.lock().unwrap();
                g.error = true;
                g.bytes_written
            };
            if let Some(obs) = &self.stor_observer {
                obs.transfer_completed(&self.stor_path, true, bytes_written, false);
            }
            if let Some(t) = self.stor_telemetry.take() {
                t.finish(false, bytes_written);
            }
            self.bridge.stor_failed();
        }
        endpoint.close();
        self.bridge.on_data_closed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::storage::StorageConfig;
    use hopf_core::{SecurityInfo, StartTlsError, TimerHandle, WriteReadyCallback};
    use std::net::SocketAddr;
    use std::time::Duration;

    /// Minimal [`Endpoint`] double that just reports a fixed remote
    /// address and tracks whether [`Endpoint::close`] was called — enough
    /// to drive [`FtpDataHandler::arm`]'s peer check deterministically,
    /// without needing a real socket pair or an actual mismatched-source-IP
    /// network setup (loopback connections from the same test process all
    /// share one source address, so a real end-to-end version of this test
    /// isn't practically constructable without extra platform-specific
    /// socket plumbing).
    struct FakeEndpoint {
        remote: SocketAddr,
        closed: bool,
        security: SecurityInfo,
    }

    impl FakeEndpoint {
        fn new(remote: SocketAddr) -> Self {
            Self {
                remote,
                closed: false,
                security: SecurityInfo::plaintext(),
            }
        }
    }

    impl Endpoint for FakeEndpoint {
        fn send(&mut self, _data: &[u8]) {}
        fn is_open(&self) -> bool {
            !self.closed
        }
        fn is_closing(&self) -> bool {
            false
        }
        fn close(&mut self) {
            self.closed = true;
        }
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok("127.0.0.1:21".parse().unwrap())
        }
        fn remote_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.remote)
        }
        fn security_info(&self) -> &SecurityInfo {
            &self.security
        }
        fn start_tls(&mut self) -> Result<(), StartTlsError> {
            Err(StartTlsError::Unsupported)
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _callback: Option<WriteReadyCallback>) {}
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn schedule_timer(&self, _delay: Duration, _callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
            TimerHandle::from_cancel(|| {})
        }
        fn handle(&self) -> ConnHandle {
            ConnHandle::from_execute(Arc::new(|task| task()))
        }
    }

    fn test_bridge() -> Arc<DataBridge> {
        let storage = Arc::new(StorageExecutor::new(StorageConfig::default()));
        let metrics = FtpServerMetrics::shared();
        DataBridge::new(storage, metrics)
    }

    /// Issue #3 (1): a data connection whose actual peer doesn't match the
    /// control connection's remote address must never be armed — this is
    /// what stops a third party that merely guesses/observes an open PASV
    /// port from reading or injecting transfer data.
    #[test]
    fn arm_rejects_data_connection_from_wrong_peer() {
        let bridge = test_bridge();
        let expected: IpAddr = "10.0.0.1".parse().unwrap();
        let mut handler = FtpDataHandler::new(Arc::clone(&bridge), false, expected);
        let mut ep = FakeEndpoint::new("10.0.0.99:4000".parse().unwrap());

        handler.connected(&mut ep);

        assert!(!handler.armed, "must not arm for a mismatched peer");
        assert!(ep.closed, "must close the connection outright");
    }

    #[test]
    fn arm_accepts_data_connection_from_matching_peer() {
        let bridge = test_bridge();
        let expected: IpAddr = "10.0.0.1".parse().unwrap();
        let mut handler = FtpDataHandler::new(Arc::clone(&bridge), false, expected);
        let mut ep = FakeEndpoint::new("10.0.0.1:4000".parse().unwrap());

        handler.connected(&mut ep);

        assert!(handler.armed, "must arm for a matching peer");
        assert!(!ep.closed);
    }

    /// Same check, but on the TLS-handshake-completion path (PROT P /
    /// `require_tls_for_data`) rather than plain `connected()`.
    #[test]
    fn arm_rejects_wrong_peer_on_security_established_path_too() {
        let bridge = test_bridge();
        let expected: IpAddr = "10.0.0.1".parse().unwrap();
        let mut handler = FtpDataHandler::new(Arc::clone(&bridge), true, expected);
        let mut ep = FakeEndpoint::new("10.0.0.99:4000".parse().unwrap());

        handler.connected(&mut ep); // expect_tls: does nothing yet
        assert!(!handler.armed);
        assert!(!ep.closed);

        handler.security_established(&mut ep, &SecurityInfo::plaintext());
        assert!(!handler.armed, "must not arm for a mismatched peer");
        assert!(ep.closed);
    }

    fn wait_for(mut pred: impl FnMut() -> bool, max_ms: u64) -> bool {
        for _ in 0..(max_ms / 5).max(1) {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        pred()
    }

    #[derive(Default)]
    struct RecordingObserver {
        progress: Mutex<Vec<Vec<u8>>>,
        completed: Mutex<Option<(u64, bool)>>,
    }

    impl TransferObserver for RecordingObserver {
        fn transfer_progress(&self, _path: &str, _upload: bool, data: &[u8], _total: u64) {
            self.progress.lock().unwrap().push(data.to_vec());
        }
        fn transfer_completed(&self, _path: &str, _upload: bool, total: u64, success: bool) {
            *self.completed.lock().unwrap() = Some((total, success));
        }
    }

    /// A `Write` whose `write` call fails starting from its `fail_at_call`th
    /// invocation — lets a test force a write failure partway through an
    /// upload without needing a real full disk.
    struct FailingWriter {
        calls: usize,
        fail_at_call: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.calls >= self.fail_at_call {
                return Err(std::io::Error::other("disk full"));
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Issue #224: STOR chunk writes must land off the reactor thread, in
    /// submission order, across many `receive()` calls — proven by feeding
    /// 20 distinct chunks and checking the resulting file byte-for-byte,
    /// not just "eventually all bytes arrived" (which alone wouldn't catch
    /// a reordering bug).
    #[test]
    fn stor_writes_land_off_thread_in_order_across_many_chunks() {
        let bridge = test_bridge();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upload.bin");
        let observer = Arc::new(RecordingObserver::default());
        bridge.queue_stor(StorTransfer {
            ascii: false,
            path: "upload.bin".to_string(),
            writer: Box::new(std::fs::File::create(&path).unwrap()),
            observer: Some(Arc::clone(&observer) as Arc<dyn TransferObserver>),
            quota: None,
            telemetry: None,
        });

        let expected: IpAddr = "10.0.0.1".parse().unwrap();
        let mut handler = FtpDataHandler::new(Arc::clone(&bridge), false, expected);
        let mut ep = FakeEndpoint::new("10.0.0.1:4000".parse().unwrap());
        handler.connected(&mut ep);
        assert!(handler.armed);

        let mut expected_bytes = Vec::new();
        for i in 0..20u8 {
            let chunk = vec![i; 500];
            expected_bytes.extend_from_slice(&chunk);
            let mut data: &[u8] = &chunk;
            handler.receive(&mut ep, &mut data);
        }
        handler.disconnected(&mut ep);

        assert!(
            wait_for(
                || std::fs::read(&path).map(|b| b.len()).unwrap_or(0) == expected_bytes.len(),
                3000
            ),
            "all chunks must eventually land on disk"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            expected_bytes,
            "bytes must land in submission order despite being offloaded per chunk"
        );
        assert!(
            wait_for(|| observer.completed.lock().unwrap().is_some(), 3000),
            "transfer_completed must eventually fire"
        );
        assert_eq!(*observer.completed.lock().unwrap(), Some((expected_bytes.len() as u64, true)));
    }

    /// Issue #224 (found while fixing it): a genuine write failure partway
    /// through an upload must be reported as a failure — the old
    /// synchronous code (`let _ = w.write_all(...)`) silently ignored
    /// write errors and would have reported success regardless.
    #[test]
    fn stor_write_failure_is_reported_as_failure_not_silently_dropped() {
        let bridge = test_bridge();
        let observer = Arc::new(RecordingObserver::default());
        bridge.queue_stor(StorTransfer {
            ascii: false,
            path: "upload.bin".to_string(),
            writer: Box::new(FailingWriter { calls: 0, fail_at_call: 2 }),
            observer: Some(Arc::clone(&observer) as Arc<dyn TransferObserver>),
            quota: None,
            telemetry: None,
        });

        let expected: IpAddr = "10.0.0.1".parse().unwrap();
        let mut handler = FtpDataHandler::new(Arc::clone(&bridge), false, expected);
        let mut ep = FakeEndpoint::new("10.0.0.1:4000".parse().unwrap());
        handler.connected(&mut ep);

        // First chunk succeeds (call 1), second chunk fails (call 2).
        let mut first: &[u8] = b"first chunk ok";
        handler.receive(&mut ep, &mut first);
        let mut second: &[u8] = b"second chunk fails";
        handler.receive(&mut ep, &mut second);
        handler.disconnected(&mut ep);

        assert!(
            wait_for(|| observer.completed.lock().unwrap().is_some(), 3000),
            "transfer_completed must eventually fire even on a write failure"
        );
        let (total, success) = observer.completed.lock().unwrap().unwrap();
        assert!(!success, "a real write failure must be reported as failure, not silently as success");
        assert_eq!(total, "first chunk ok".len() as u64, "reported total must reflect only what actually landed");
    }
}
