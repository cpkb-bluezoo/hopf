// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Data-connection bridge and handler (PASV accept / active dial).

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, StorageExecutor};

use crate::ascii::normalize_ascii_newlines;
use crate::metrics::FtpServerMetrics;
use crate::reply::reply;

/// Outbound (server→client) transfer.
pub enum OutboundTransfer {
    /// RETR file body.
    Retr {
        /// TYPE A.
        ascii: bool,
        /// Reader.
        reader: Box<dyn Read + Send>,
    },
    /// Preformatted listing.
    Listing {
        /// Bytes.
        body: Vec<u8>,
    },
}

/// Shared state between control and one data connection.
pub struct DataBridge {
    inner: Mutex<DataBridgeState>,
}

struct DataBridgeState {
    data_handle: Option<ConnHandle>,
    control_handle: Option<ConnHandle>,
    outbound: Option<OutboundTransfer>,
    stor_writer: Option<Box<dyn Write + Send>>,
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
                stor_writer: None,
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
    pub fn queue_outbound(&self, transfer: OutboundTransfer) {
        {
            let mut g = self.inner.lock().unwrap();
            g.outbound = Some(transfer);
        }
        self.try_start_outbound();
    }

    /// Queue STOR / APPE writer for the data handler.
    pub fn queue_stor(&self, writer: Box<dyn Write + Send>) {
        self.inner.lock().unwrap().stor_writer = Some(writer);
    }

    /// Data peer connected.
    pub fn on_data_connected(&self, handle: ConnHandle) {
        self.inner.lock().unwrap().data_handle = Some(handle);
        self.try_start_outbound();
    }

    /// Take STOR writer (data handler).
    pub fn take_stor_writer(&self) -> Option<Box<dyn Write + Send>> {
        self.inner.lock().unwrap().stor_writer.take()
    }

    /// Data peer closed.
    pub fn on_data_closed(&self) {
        self.inner.lock().unwrap().data_handle = None;
    }

    /// Finish STOR successfully.
    pub fn stor_complete(&self, bytes: u64) {
        let g = self.inner.lock().unwrap();
        FtpServerMetrics::add(&g.metrics.bytes_in, bytes);
        if let Some(c) = &g.control_handle {
            c.send(reply(226, "Transfer complete"));
        }
    }

    /// Finish STOR with error.
    pub fn stor_failed(&self) {
        let g = self.inner.lock().unwrap();
        if let Some(c) = &g.control_handle {
            c.send(reply(426, "Transfer aborted"));
        }
    }

    fn try_start_outbound(&self) {
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

        match transfer {
            OutboundTransfer::Retr { ascii, mut reader } => {
                storage.submit_on(
                    data.clone(),
                    move || {
                        let mut buf = Vec::new();
                        reader.read_to_end(&mut buf)?;
                        let out = if ascii {
                            normalize_ascii_newlines(&buf)
                        } else {
                            buf
                        };
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(out)
                    },
                    move |result| match result {
                        Ok(bytes) => {
                            let n = bytes.len() as u64;
                            FtpServerMetrics::add(&metrics.bytes_out, n);
                            data.send(bytes);
                            data.close();
                            if let Some(c) = control {
                                c.send(reply(226, "Transfer complete"));
                            }
                        }
                        Err(_) => {
                            data.close();
                            if let Some(c) = control {
                                c.send(reply(426, "Transfer aborted"));
                            }
                        }
                    },
                );
            }
            OutboundTransfer::Listing { body } => {
                let n = body.len() as u64;
                FtpServerMetrics::add(&metrics.bytes_out, n);
                data.send(body);
                data.close();
                if let Some(c) = control {
                    c.send(reply(226, "Transfer complete"));
                }
            }
        }
    }
}

/// Protocol handler for one data connection.
pub struct FtpDataHandler {
    bridge: Arc<DataBridge>,
    /// When true, wait for [`ProtocolHandler::security_established`] before arming.
    expect_tls: bool,
    armed: bool,
    stor_writer: Option<Box<dyn Write + Send>>,
    stor_bytes: u64,
}

impl FtpDataHandler {
    /// Create for an accepted/dialed data socket.
    pub fn new(bridge: Arc<DataBridge>, expect_tls: bool) -> Self {
        Self {
            bridge,
            expect_tls,
            armed: false,
            stor_writer: None,
            stor_bytes: 0,
        }
    }

    fn arm(&mut self, endpoint: &mut dyn Endpoint) {
        if self.armed {
            return;
        }
        self.armed = true;
        let handle = endpoint.handle();
        self.bridge.on_data_connected(handle);
        self.stor_writer = self.bridge.take_stor_writer();
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
        if self.stor_writer.is_none() {
            self.stor_writer = self.bridge.take_stor_writer();
        }
        if let Some(w) = self.stor_writer.as_mut() {
            let _ = w.write_all(*data);
            self.stor_bytes += data.len() as u64;
        }
        *data = &[];
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if let Some(mut w) = self.stor_writer.take() {
            let _ = w.flush();
            self.bridge.stor_complete(self.stor_bytes);
        }
        self.bridge.on_data_closed();
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &std::io::Error) {
        if self.stor_writer.take().is_some() {
            self.bridge.stor_failed();
        }
        endpoint.close();
        self.bridge.on_data_closed();
    }
}
