// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared H3 request-stream response state for in-callback and deferred writes.

use std::sync::{Arc, Mutex};

use hopf_core::ConnHandle;

use crate::headers::Headers;
use crate::stream::{ProtocolUpgradeHandler, ResponseControl, ServerResponseHandle, ServerWriter};

/// Outbound response fields for one HTTP/3 request stream.
pub(crate) struct H3WriterShared {
    pub headers: Option<Headers>,
    pub trailers: Option<Headers>,
    pub body: Vec<u8>,
    pub complete: bool,
    pub body_paused: bool,
    pub needs_flush: bool,
    pub upgrade_handler: Option<Box<dyn ProtocolUpgradeHandler>>,
    pub upgraded: bool,
    pub headers_sent: bool,
}

impl H3WriterShared {
    fn new() -> Self {
        Self {
            headers: None,
            trailers: None,
            body: Vec::new(),
            complete: false,
            body_paused: false,
            needs_flush: false,
            upgrade_handler: None,
            upgraded: false,
            headers_sent: false,
        }
    }
}

pub(crate) struct H3ResponseControl {
    conn: Mutex<ConnHandle>,
    flush: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    pub shared: Arc<Mutex<H3WriterShared>>,
}

impl H3ResponseControl {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            conn: Mutex::new(ConnHandle::from_execute(Arc::new(|task| task()))),
            flush: Mutex::new(None),
            shared: Arc::new(Mutex::new(H3WriterShared::new())),
        })
    }

    pub(crate) fn bind_conn(&self, conn: ConnHandle) {
        *self.conn.lock().unwrap() = conn;
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

    #[allow(dead_code)]
    pub(crate) fn needs_flush(&self) -> bool {
        self.shared.lock().unwrap().needs_flush
    }

    #[allow(dead_code)]
    pub(crate) fn clear_needs_flush(&self) {
        self.shared.lock().unwrap().needs_flush = false;
    }

    pub(crate) fn take_upgrade(&self) -> Option<Box<dyn ProtocolUpgradeHandler>> {
        self.shared.lock().unwrap().upgrade_handler.take()
    }

    pub(crate) fn writer(self: &Arc<Self>) -> H3SessionWriter {
        H3SessionWriter {
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

pub(crate) struct ArcH3ResponseControl {
    inner: Arc<H3ResponseControl>,
}

impl ArcH3ResponseControl {
    pub(crate) fn new(inner: Arc<H3ResponseControl>) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}

impl ResponseControl for ArcH3ResponseControl {
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

pub(crate) struct H3SessionWriter {
    control: Arc<H3ResponseControl>,
}

impl H3SessionWriter {
    fn with_shared<R>(&mut self, f: impl FnOnce(&mut H3WriterShared) -> R) -> R {
        let mut s = self.control.shared.lock().unwrap();
        f(&mut s)
    }
}

impl ServerWriter for H3SessionWriter {
    fn headers(&mut self, headers: Headers) {
        self.with_shared(|s| {
            s.headers = Some(headers);
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
            s.complete = true;
        });
    }

    fn trailers(&mut self, headers: Headers) {
        self.with_shared(|s| {
            s.trailers = Some(headers);
            s.complete = true;
        });
    }

    fn complete(&mut self) {
        self.with_shared(|s| {
            s.complete = true;
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
            s.headers = Some(headers);
            s.complete = false;
            s.upgraded = true;
            s.upgrade_handler = Some(handler);
            true
        })
    }

    fn conn_handle(&self) -> ConnHandle {
        self.control.conn_handle()
    }

    fn response_handle(&self) -> ServerResponseHandle {
        ServerResponseHandle::new(ArcH3ResponseControl::new(Arc::clone(&self.control)))
    }

    fn pause_request_body(&mut self) {
        self.control.pause_request_body();
    }

    fn resume_request_body(&mut self) {
        self.control.resume_request_body();
    }
}
