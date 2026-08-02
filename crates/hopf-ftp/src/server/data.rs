// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Data-connection bridge and handler (PASV accept / active dial).

use std::io::{Read, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, StorageExecutor};

use crate::server::ascii::{AsciiNewlineDenormalizer, AsciiNewlineNormalizer};
use crate::server::handler::TransferObserver;
use crate::server::metrics::FtpServerMetrics;
use crate::server::reply::reply;

/// Bounded read chunk size for streamed RETR transfers.
const RETR_CHUNK_SIZE: usize = 8192;

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
    },
    /// Preformatted listing.
    Listing {
        /// Bytes.
        body: Vec<u8>,
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
            OutboundTransfer::Retr { ascii, mut reader, path, observer } => {
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
                    move |result| match result {
                        Ok(n) => {
                            FtpServerMetrics::add(&metrics.bytes_out, n);
                            if let Some(obs) = &complete_observer {
                                obs.transfer_completed(&complete_path, false, n, true);
                            }
                            data.close();
                            Self::send_transfer_reply(&control, bridge_done.was_aborted(), true);
                        }
                        Err(_) => {
                            if let Some(obs) = &complete_observer {
                                obs.transfer_completed(&complete_path, false, 0, false);
                            }
                            data.close();
                            Self::send_transfer_reply(&control, bridge_done.was_aborted(), false);
                        }
                    },
                );
            }
            OutboundTransfer::Listing { body } => {
                if bridge.was_aborted() {
                    data.close();
                    return;
                }
                let n = body.len() as u64;
                FtpServerMetrics::add(&metrics.bytes_out, n);
                data.send(body);
                data.close();
                Self::send_transfer_reply(&control, bridge.was_aborted(), true);
            }
        }
    }
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
    stor_writer: Option<Box<dyn Write + Send>>,
    stor_path: String,
    stor_observer: Option<Arc<dyn TransferObserver>>,
    stor_quota: Option<(Arc<dyn hopf_core::QuotaManager>, String)>,
    stor_bytes: u64,
    stor_ascii: bool,
    stor_denorm: AsciiNewlineDenormalizer,
}

impl FtpDataHandler {
    /// Create for an accepted/dialed data socket.
    pub fn new(bridge: Arc<DataBridge>, expect_tls: bool, expected_peer: IpAddr) -> Self {
        Self {
            bridge,
            expect_tls,
            expected_peer,
            armed: false,
            stor_writer: None,
            stor_path: String::new(),
            stor_observer: None,
            stor_quota: None,
            stor_bytes: 0,
            stor_ascii: false,
            stor_denorm: AsciiNewlineDenormalizer::new(),
        }
    }

    /// Pull in a queued [`StorTransfer`], if one is waiting and we haven't
    /// already got one — the data connection can arm (or start receiving,
    /// for active mode) before the control connection has actually queued
    /// the transfer, so both [`Self::arm`] and
    /// [`ProtocolHandler::receive`](ProtocolHandler) retry this.
    fn take_stor(&mut self) {
        if self.stor_writer.is_none() {
            if let Some(t) = self.bridge.take_stor_transfer() {
                self.stor_path = t.path;
                self.stor_observer = t.observer;
                self.stor_quota = t.quota;
                self.stor_ascii = t.ascii;
                self.stor_denorm = AsciiNewlineDenormalizer::new();
                self.stor_writer = Some(t.writer);
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
        if let Some(w) = self.stor_writer.as_mut() {
            if self.stor_ascii {
                let mut out = Vec::with_capacity(data.len());
                self.stor_denorm.feed(data, &mut out);
                if !out.is_empty() {
                    let _ = w.write_all(&out);
                    self.stor_bytes += out.len() as u64;
                    if let Some(obs) = &self.stor_observer {
                        obs.transfer_progress(&self.stor_path, true, &out, self.stor_bytes);
                    }
                }
            } else {
                let _ = w.write_all(*data);
                self.stor_bytes += data.len() as u64;
                if let Some(obs) = &self.stor_observer {
                    obs.transfer_progress(&self.stor_path, true, data, self.stor_bytes);
                }
            }
        }
        *data = &[];
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if let Some(mut w) = self.stor_writer.take() {
            if self.stor_ascii {
                let mut tail = Vec::new();
                self.stor_denorm.finish(&mut tail);
                if !tail.is_empty() {
                    let _ = w.write_all(&tail);
                    self.stor_bytes += tail.len() as u64;
                    if let Some(obs) = &self.stor_observer {
                        obs.transfer_progress(&self.stor_path, true, &tail, self.stor_bytes);
                    }
                }
            }
            let _ = w.flush();
            if self.bridge.was_aborted() {
                if let Some(obs) = &self.stor_observer {
                    obs.transfer_completed(&self.stor_path, true, self.stor_bytes, false);
                }
            } else {
                if let Some(obs) = &self.stor_observer {
                    obs.transfer_completed(&self.stor_path, true, self.stor_bytes, true);
                }
                if let Some((qm, user)) = &self.stor_quota {
                    qm.record_bytes_added(user, self.stor_bytes);
                }
                self.bridge.stor_complete(self.stor_bytes);
            }
        }
        self.bridge.on_data_closed();
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &std::io::Error) {
        if self.stor_writer.take().is_some() {
            if let Some(obs) = &self.stor_observer {
                obs.transfer_completed(&self.stor_path, true, self.stor_bytes, false);
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
}
