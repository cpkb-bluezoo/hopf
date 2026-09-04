// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared H2 stream response state for in-callback and deferred writes.

use std::sync::{Arc, Mutex};

use hopf_core::ConnHandle;

use crate::headers::Headers;
use crate::stream::{
    ConnectionInfo, ProtocolUpgradeHandler, ResponseControl, ServerResponseHandle, ServerWriter,
};

/// Outbound response fields for one server stream (shared with deferred execute).
pub(crate) struct H2WriterShared {
    pub response_headers: Option<Headers>,
    /// Trailer headers (second HEADERS + END_STREAM after DATA).
    pub trailers: Option<Headers>,
    pub body: Vec<u8>,
    pub done: bool,
    pub headers_sent: bool,
    /// Stream-scoped: withhold request DATA from the handler while true.
    pub body_paused: bool,
    /// Deferred execute wrote; connection should flush this stream.
    pub needs_flush: bool,
    /// Protocol upgrade (WebSocket Extended CONNECT, etc.).
    pub upgrade_handler: Option<Box<dyn ProtocolUpgradeHandler>>,
    /// Stream is an upgraded byte tunnel — never END_STREAM on response headers.
    pub upgraded: bool,
}

impl H2WriterShared {
    fn new() -> Self {
        Self {
            response_headers: None,
            trailers: None,
            body: Vec::new(),
            done: false,
            headers_sent: false,
            body_paused: false,
            needs_flush: false,
            upgrade_handler: None,
            upgraded: false,
        }
    }
}

/// Per-stream control: ConnHandle + shared writer state.
pub(crate) struct H2ResponseControl {
    #[allow(dead_code)]
    pub stream_id: u32,
    conn: Mutex<ConnHandle>,
    connection_info: Mutex<ConnectionInfo>,
    flush: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    pub shared: Arc<Mutex<H2WriterShared>>,
}

impl H2ResponseControl {
    pub(crate) fn new(stream_id: u32) -> Arc<Self> {
        Arc::new(Self {
            stream_id,
            conn: Mutex::new(ConnHandle::from_execute(Arc::new(|task| task()))),
            connection_info: Mutex::new(ConnectionInfo::default()),
            flush: Mutex::new(None),
            shared: Arc::new(Mutex::new(H2WriterShared::new())),
        })
    }

    pub(crate) fn bind_conn(&self, conn: ConnHandle) {
        *self.conn.lock().unwrap() = conn;
    }

    pub(crate) fn bind_connection_info(&self, info: ConnectionInfo) {
        *self.connection_info.lock().unwrap() = info;
    }

    pub(crate) fn connection_info(&self) -> ConnectionInfo {
        self.connection_info.lock().unwrap().clone()
    }

    pub(crate) fn set_flush(&self, flush: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.flush.lock().unwrap() = flush;
    }

    pub(crate) fn conn_handle(&self) -> ConnHandle {
        self.conn.lock().unwrap().clone()
    }

    pub(crate) fn body_paused(&self) -> bool {
        self.shared.lock().unwrap().body_paused
    }

    pub(crate) fn take_upgrade(&self) -> Option<Box<dyn ProtocolUpgradeHandler>> {
        self.shared.lock().unwrap().upgrade_handler.take()
    }

    pub(crate) fn writer(self: &Arc<Self>) -> H2SessionWriter {
        H2SessionWriter {
            control: Arc::clone(self),
        }
    }

    fn try_flush_after_execute(self: &Arc<Self>) {
        self.shared.lock().unwrap().needs_flush = true;
        if let Some(cb) = self.flush.lock().unwrap().clone() {
            cb();
        }
    }

    fn pause_request_body(&self) {
        self.shared.lock().unwrap().body_paused = true;
    }

    fn resume_request_body(&self) {
        self.shared.lock().unwrap().body_paused = false;
        if let Some(cb) = self.flush.lock().unwrap().clone() {
            cb();
        }
    }
}

/// Arc-aware [`ResponseControl`] for reactor [`ConnHandle::execute`](ConnHandle::execute).
pub(crate) struct ArcH2ResponseControl {
    inner: Arc<H2ResponseControl>,
}

impl ArcH2ResponseControl {
    pub(crate) fn new(inner: Arc<H2ResponseControl>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

impl ResponseControl for ArcH2ResponseControl {
    fn conn_handle(&self) -> ConnHandle {
        self.inner.conn_handle()
    }

    fn execute(&self, f: Box<dyn FnOnce(&mut dyn ServerWriter) + Send>) {
        let control = Arc::clone(&self.inner);
        let conn = control.conn_handle();
        conn.execute(Box::new(move || {
            let mut writer = control.writer();
            f(&mut writer);
            control.try_flush_after_execute();
        }));
    }

    fn pause_request_body(&self) {
        self.inner.pause_request_body();
    }

    fn resume_request_body(&self) {
        self.inner.resume_request_body();
    }
}

/// [`ServerWriter`] over shared H2 stream response state.
pub(crate) struct H2SessionWriter {
    control: Arc<H2ResponseControl>,
}

impl H2SessionWriter {
    fn with_shared<R>(&mut self, f: impl FnOnce(&mut H2WriterShared) -> R) -> R {
        let mut s = self.control.shared.lock().unwrap();
        f(&mut s)
    }
}

impl ServerWriter for H2SessionWriter {
    fn headers(&mut self, headers: Headers) {
        self.with_shared(|s| {
            s.response_headers = Some(headers);
        });
    }

    fn start_response_body(&mut self) {}

    fn response_body_content(&mut self, data: &[u8]) {
        self.with_shared(|s| {
            s.body.extend_from_slice(data);
        });
    }

    fn end_response_body(&mut self) {
        self.with_shared(|s| {
            s.done = true;
        });
    }

    fn trailers(&mut self, headers: Headers) {
        self.with_shared(|s| {
            s.trailers = Some(headers);
            s.done = true;
        });
    }

    fn complete(&mut self) {
        self.with_shared(|s| {
            s.done = true;
        });
    }

    fn upgrade(
        &mut self,
        headers: Headers,
        handler: Box<dyn ProtocolUpgradeHandler>,
    ) -> bool {
        self.with_shared(|s| {
            if s.headers_sent || s.upgrade_handler.is_some() || s.upgraded {
                return false;
            }
            s.response_headers = Some(headers);
            s.done = false;
            s.upgraded = true;
            s.upgrade_handler = Some(handler);
            true
        })
    }

    fn conn_handle(&self) -> ConnHandle {
        self.control.conn_handle()
    }

    fn connection_info(&self) -> ConnectionInfo {
        self.control.connection_info()
    }

    fn response_handle(&self) -> ServerResponseHandle {
        ServerResponseHandle::new(ArcH2ResponseControl::new(Arc::clone(&self.control)))
    }

    fn pause_request_body(&mut self) {
        self.control.pause_request_body();
    }

    fn resume_request_body(&mut self) {
        self.control.resume_request_body();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::Headers;

    #[test]
    fn trailers_buffered_with_done() {
        let control = H2ResponseControl::new(1);
        let mut w = control.writer();
        let mut h = Headers::new();
        h.status(200);
        w.headers(h);
        w.response_body_content(b"abc");
        let mut t = Headers::new();
        t.set("grpc-status", "0");
        w.trailers(t);
        let shared = control.shared.lock().unwrap();
        assert!(shared.done);
        assert_eq!(
            shared.trailers.as_ref().and_then(|h| h.get("grpc-status")),
            Some("0")
        );
        assert_eq!(shared.body, b"abc");
    }

    #[test]
    fn connection_info_round_trips_through_writer() {
        let control = H2ResponseControl::new(1);
        let remote: std::net::SocketAddr = "203.0.113.5:9000".parse().unwrap();
        let local: std::net::SocketAddr = "198.51.100.7:443".parse().unwrap();
        let info = ConnectionInfo::new(
            Some(hopf_core::PeerAddr::Inet(remote)),
            Some(hopf_core::PeerAddr::Inet(local)),
            hopf_core::SecurityInfo::secure(
                Some(b"h2".to_vec()),
                Some("TLSv1.3".into()),
                Some("TLS_AES_128_GCM_SHA256".into()),
            ),
        );
        control.bind_connection_info(info);

        let w = control.writer();
        let got = ServerWriter::connection_info(&w);
        assert_eq!(got.remote_addr(), Some(hopf_core::PeerAddr::Inet(remote)));
        assert_eq!(got.local_addr(), Some(hopf_core::PeerAddr::Inet(local)));
        assert!(got.is_secure());
        assert_eq!(got.security_info().alpn(), Some(&b"h2"[..]));
    }
}
