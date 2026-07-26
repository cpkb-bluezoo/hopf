// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared H1 response session for in-callback and deferred writes.

use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Endpoint};

use crate::headers::Headers;
use crate::status::reason_phrase;
use crate::stream::{
    ProtocolUpgradeHandler, ResponseControl, ServerResponseHandle, ServerWriter,
};
use crate::utils::http_date_now;
use crate::version::HttpVersion;

/// Framing + outbound buffer shared by the codec driver and deferred
/// [`ServerResponseHandle::execute`](ServerResponseHandle::execute).
pub(crate) struct H1ResponseShared {
    pub out: Vec<u8>,
    pub close_connection: bool,
    pub response_headers: Option<Headers>,
    pub response_headers_sent: bool,
    pub response_chunked: bool,
    pub response_ended: bool,
    pub method: String,
    pub version: HttpVersion,
    /// When true, [`H1Endpoint`](super::endpoint::H1Endpoint) should `pause_read`.
    pub pause_request_body: bool,
    /// Set when execute wrote bytes but `with_endpoint` could not flush.
    pub needs_flush: bool,
    /// Pending protocol upgrade handler (WebSocket, etc.).
    pub upgrade_handler: Option<Box<dyn ProtocolUpgradeHandler>>,
}

impl H1ResponseShared {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            close_connection: false,
            response_headers: None,
            response_headers_sent: false,
            response_chunked: false,
            response_ended: false,
            method: String::new(),
            version: HttpVersion::Http11,
            pause_request_body: false,
            needs_flush: false,
            upgrade_handler: None,
        }
    }

    fn reset_message(&mut self) {
        self.response_headers = None;
        self.response_headers_sent = false;
        self.response_chunked = false;
        self.response_ended = false;
        self.method.clear();
        self.pause_request_body = false;
        // Keep `close_connection` across messages when Connection: close / HTTP/1.0.
        // Keep upgrade_handler — connection leaves HTTP after upgrade.
    }
}

/// H1 session: ConnHandle + shared framing + optional flush callback.
pub(crate) struct H1ResponseControl {
    conn: Mutex<ConnHandle>,
    /// Invoked after deferred writes when `with_endpoint` is unavailable.
    flush: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    shared: Arc<Mutex<H1ResponseShared>>,
}

impl H1ResponseControl {
    pub(crate) fn new() -> Arc<Self> {
        // Default: run tasks inline (codec unit tests / before TCP bind).
        let conn = ConnHandle::from_execute(Arc::new(|task| task()));
        Arc::new(Self {
            conn: Mutex::new(conn),
            flush: Mutex::new(None),
            shared: Arc::new(Mutex::new(H1ResponseShared::new())),
        })
    }

    pub(crate) fn bind_conn(&self, conn: ConnHandle) {
        *self.conn.lock().unwrap() = conn;
    }

    /// Optional flush hook for `from_execute`-only handles (no `with_endpoint`).
    #[allow(dead_code)]
    pub(crate) fn set_flush(&self, flush: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.flush.lock().unwrap() = flush;
    }

    pub(crate) fn conn_handle(&self) -> ConnHandle {
        self.conn.lock().unwrap().clone()
    }

    pub(crate) fn take_outbound(&self) -> Vec<u8> {
        let mut s = self.shared.lock().unwrap();
        s.needs_flush = false;
        std::mem::take(&mut s.out)
    }

    /// Take a pending protocol-upgrade handler, if any.
    pub(crate) fn take_upgrade(&self) -> Option<Box<dyn ProtocolUpgradeHandler>> {
        self.shared.lock().unwrap().upgrade_handler.take()
    }

    pub(crate) fn wants_close(&self) -> bool {
        let s = self.shared.lock().unwrap();
        // Do not close until the response has finished — deferred
        // `ServerResponseHandle::execute` may still need to write.
        s.close_connection && s.response_ended
    }

    pub(crate) fn pause_request_body_flag(&self) -> bool {
        self.shared.lock().unwrap().pause_request_body
    }

    pub(crate) fn needs_flush(&self) -> bool {
        self.shared.lock().unwrap().needs_flush
    }

    pub(crate) fn reset_message_fields(&self) {
        self.shared.lock().unwrap().reset_message();
    }

    pub(crate) fn set_version(&self, version: HttpVersion) {
        self.shared.lock().unwrap().version = version;
    }

    pub(crate) fn set_close_connection(&self, close: bool) {
        self.shared.lock().unwrap().close_connection = close;
    }

    pub(crate) fn set_method(&self, method: &str) {
        self.shared.lock().unwrap().method = method.to_string();
    }

    pub(crate) fn writer(self: &Arc<Self>) -> H1SessionWriter {
        H1SessionWriter {
            control: Arc::clone(self),
        }
    }

    pub(crate) fn write_error_response(&self, status: u16) {
        let mut s = self.shared.lock().unwrap();
        if status == 0 || s.response_headers_sent {
            return;
        }
        let reason = reason_phrase(status);
        let ver = s.version.as_str();
        let body = format!("{status} {reason}");
        let msg = format!(
            "{ver} {status} {reason}\r\n\
             Connection: close\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {body}",
            body.len()
        );
        s.out.extend_from_slice(msg.as_bytes());
        s.response_headers_sent = true;
        s.response_ended = true;
        s.close_connection = true;
    }

    pub(crate) fn extend_out(&self, bytes: &[u8]) {
        self.shared.lock().unwrap().out.extend_from_slice(bytes);
    }

    fn apply_pause_to_endpoint(ep: &mut dyn Endpoint, pause: bool) {
        if pause {
            ep.pause_read();
        } else {
            ep.resume_read();
        }
    }

    fn flush_to_endpoint(self: &Arc<Self>, ep: &mut dyn Endpoint) {
        let out = self.take_outbound();
        if !out.is_empty() {
            ep.send(&out);
        }
        Self::apply_pause_to_endpoint(ep, self.pause_request_body_flag());
    }

    fn try_flush_after_execute(self: &Arc<Self>) {
        let conn = self.conn_handle();
        let this = Arc::clone(self);
        // TCP ConnHandle: re-enter endpoint and send. Tasks-only: no-op.
        conn.with_endpoint(move |ep| {
            this.flush_to_endpoint(ep);
        });
        // from_execute path: leave bytes in the shared buffer for take_outbound /
        // the next H1Endpoint::receive, and optionally run a flush callback.
        if let Some(cb) = self.flush.lock().unwrap().clone() {
            cb();
        } else {
            self.shared.lock().unwrap().needs_flush = true;
        }
    }

    fn pause_request_body(&self) {
        self.shared.lock().unwrap().pause_request_body = true;
        let conn = self.conn_handle();
        conn.with_endpoint(|ep| ep.pause_read());
    }

    fn resume_request_body(&self) {
        self.shared.lock().unwrap().pause_request_body = false;
        let conn = self.conn_handle();
        conn.with_endpoint(|ep| ep.resume_read());
    }
}

/// Arc-aware [`ResponseControl`] so `execute` can clone into reactor tasks.
pub(crate) struct ArcH1ResponseControl {
    inner: Arc<H1ResponseControl>,
}

impl ArcH1ResponseControl {
    pub(crate) fn new(inner: Arc<H1ResponseControl>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

impl ResponseControl for ArcH1ResponseControl {
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

/// [`ServerWriter`] over the shared H1 response session.
pub(crate) struct H1SessionWriter {
    control: Arc<H1ResponseControl>,
}

impl H1SessionWriter {
    fn with_shared<R>(&mut self, f: impl FnOnce(&mut H1ResponseShared) -> R) -> R {
        let mut s = self.control.shared.lock().unwrap();
        f(&mut s)
    }

    fn flush_response_headers(s: &mut H1ResponseShared) {
        if s.response_headers_sent {
            return;
        }
        let mut headers = s.response_headers.take().unwrap_or_default();
        if !headers.contains(":status") {
            headers.status(200);
        }
        let status = headers.status_code();
        if !headers.contains("server") {
            headers.set("Server", "hopf");
        }
        if !headers.contains("date") {
            headers.set("Date", http_date_now());
        }
        let auto_chunk = s.version == HttpVersion::Http11
            && status >= 200
            && status != 204
            && status != 304
            && s.method != "HEAD"
            && !headers.contains("content-length")
            && !headers.contains("transfer-encoding");
        if auto_chunk {
            headers.set("Transfer-Encoding", "chunked");
            s.response_chunked = true;
        }
        let reason = reason_phrase(status);
        let mut msg = format!("{} {status} {reason}\r\n", s.version.as_str());
        for h in headers.iter() {
            if h.name.starts_with(':') {
                continue;
            }
            msg.push_str(&format!("{}: {}\r\n", h.name, h.value));
        }
        msg.push_str("\r\n");
        s.out.extend_from_slice(msg.as_bytes());
        s.response_headers_sent = true;
    }
}

impl ServerWriter for H1SessionWriter {
    fn send_informational(&mut self, code: u16, headers: &Headers) {
        self.with_shared(|s| {
            if s.response_headers_sent || code < 100 || code > 199 {
                return;
            }
            let reason = reason_phrase(code);
            let mut msg = format!("{} {code} {reason}\r\n", s.version.as_str());
            for h in headers.iter() {
                if h.name.starts_with(':') {
                    continue;
                }
                msg.push_str(&format!("{}: {}\r\n", h.name, h.value));
            }
            msg.push_str("\r\n");
            s.out.extend_from_slice(msg.as_bytes());
        });
    }

    fn headers(&mut self, mut headers: Headers) {
        self.with_shared(|s| {
            if s.response_headers_sent {
                return;
            }
            if s.close_connection && !headers.contains("connection") {
                headers.set("Connection", "close");
            }
            s.response_headers = Some(headers);
        });
    }

    fn start_response_body(&mut self) {
        self.with_shared(Self::flush_response_headers);
    }

    fn response_body_content(&mut self, data: &[u8]) {
        self.with_shared(|s| {
            if !s.response_headers_sent {
                Self::flush_response_headers(s);
            }
            if s.method == "HEAD" || s.response_ended {
                return;
            }
            if s.response_chunked {
                let hdr = format!("{:x}\r\n", data.len());
                s.out.extend_from_slice(hdr.as_bytes());
                s.out.extend_from_slice(data);
                s.out.extend_from_slice(b"\r\n");
            } else {
                s.out.extend_from_slice(data);
            }
        });
    }

    fn end_response_body(&mut self) {
        self.with_shared(|s| {
            if !s.response_headers_sent {
                Self::flush_response_headers(s);
            }
            if s.response_chunked && s.method != "HEAD" {
                s.out.extend_from_slice(b"0\r\n\r\n");
            }
            s.response_ended = true;
        });
    }

    fn complete(&mut self) {
        self.with_shared(|s| {
            if !s.response_headers_sent {
                Self::flush_response_headers(s);
            }
            if s.response_chunked && !s.response_ended && s.method != "HEAD" {
                s.out.extend_from_slice(b"0\r\n\r\n");
            }
            s.response_ended = true;
        });
    }

    fn upgrade(
        &mut self,
        headers: Headers,
        handler: Box<dyn ProtocolUpgradeHandler>,
    ) -> bool {
        let mut s = self.control.shared.lock().unwrap();
        if s.response_headers_sent || s.upgrade_handler.is_some() {
            return false;
        }
        s.response_headers = Some(headers);
        s.response_chunked = false;
        Self::flush_response_headers(&mut s);
        s.response_ended = true;
        s.upgrade_handler = Some(handler);
        true
    }

    fn conn_handle(&self) -> ConnHandle {
        self.control.conn_handle()
    }

    fn response_handle(&self) -> ServerResponseHandle {
        ServerResponseHandle::new(ArcH1ResponseControl::new(Arc::clone(&self.control)))
    }

    fn pause_request_body(&mut self) {
        self.control.shared.lock().unwrap().pause_request_body = true;
    }

    fn resume_request_body(&mut self) {
        self.control.shared.lock().unwrap().pause_request_body = false;
    }
}
