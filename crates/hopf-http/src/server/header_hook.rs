// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! A decorator that lets one function adjust every response's headers.
//!
//! [`HeaderHookFactory`] wraps a [`ServerHandlerFactory`] and calls a hook
//! with the response headers (and the connection's [`ConnectionInfo`]) just
//! before they reach the transport. It sees every response: ones written in
//! a request callback and ones a handler produces later through
//! [`ServerResponseHandle::execute`].

use std::sync::Arc;

use hopf_core::ConnHandle;

use crate::headers::Headers;
use crate::stream::{
    ConnectionInfo, ProtocolUpgradeHandler, ResponseControl, ServerHandler, ServerHandlerFactory,
    ServerResponseHandle, ServerWriter,
};

/// Adjusts response headers in place.
pub(crate) type HeaderHook = dyn Fn(&mut Headers, &ConnectionInfo) + Send + Sync;

pub(crate) struct HeaderHookFactory {
    inner: Arc<dyn ServerHandlerFactory>,
    hook: Arc<HeaderHook>,
}

impl HeaderHookFactory {
    pub(crate) fn new(inner: Arc<dyn ServerHandlerFactory>, hook: Arc<HeaderHook>) -> Self {
        Self { inner, hook }
    }
}

impl ServerHandlerFactory for HeaderHookFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(HookHandler {
            inner: self.inner.create_handler(),
            hook: Arc::clone(&self.hook),
        })
    }
}

struct HookWriter<'a> {
    inner: &'a mut dyn ServerWriter,
    hook: Arc<HeaderHook>,
}

impl ServerWriter for HookWriter<'_> {
    fn send_informational(&mut self, code: u16, headers: &Headers) {
        self.inner.send_informational(code, headers);
    }

    fn headers(&mut self, mut headers: Headers) {
        let info = self.inner.connection_info();
        (self.hook)(&mut headers, &info);
        self.inner.headers(headers);
    }

    fn start_response_body(&mut self) {
        self.inner.start_response_body();
    }

    fn response_body_content(&mut self, data: &[u8]) {
        self.inner.response_body_content(data);
    }

    fn end_response_body(&mut self) {
        self.inner.end_response_body();
    }

    fn trailers(&mut self, headers: Headers) {
        self.inner.trailers(headers);
    }

    fn complete(&mut self) {
        self.inner.complete();
    }

    fn upgrade(&mut self, headers: Headers, handler: Box<dyn ProtocolUpgradeHandler>) -> bool {
        self.inner.upgrade(headers, handler)
    }

    fn traceparent(&self) -> Option<&str> {
        self.inner.traceparent()
    }

    fn conn_handle(&self) -> ConnHandle {
        self.inner.conn_handle()
    }

    fn connection_info(&self) -> ConnectionInfo {
        self.inner.connection_info()
    }

    fn response_handle(&self) -> ServerResponseHandle {
        let real = self.inner.response_handle();
        ServerResponseHandle::new(Arc::new(HookControl {
            inner: Arc::clone(real.control()),
            hook: Arc::clone(&self.hook),
        }))
    }

    fn pause_request_body(&mut self) {
        self.inner.pause_request_body();
    }

    fn resume_request_body(&mut self) {
        self.inner.resume_request_body();
    }
}

struct HookControl {
    inner: Arc<dyn ResponseControl>,
    hook: Arc<HeaderHook>,
}

impl ResponseControl for HookControl {
    fn conn_handle(&self) -> ConnHandle {
        self.inner.conn_handle()
    }

    fn execute(&self, f: Box<dyn FnOnce(&mut dyn ServerWriter) + Send>) {
        let hook = Arc::clone(&self.hook);
        self.inner.execute(Box::new(move |w| {
            let mut hw = HookWriter { inner: w, hook };
            f(&mut hw);
        }));
    }

    fn pause_request_body(&self) {
        self.inner.pause_request_body();
    }

    fn resume_request_body(&self) {
        self.inner.resume_request_body();
    }
}

struct HookHandler {
    inner: Box<dyn ServerHandler>,
    hook: Arc<HeaderHook>,
}

impl HookHandler {
    fn writer<'a>(&self, w: &'a mut dyn ServerWriter) -> HookWriter<'a> {
        HookWriter {
            inner: w,
            hook: Arc::clone(&self.hook),
        }
    }
}

impl ServerHandler for HookHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        let mut w = self.writer(response);
        self.inner.headers(&mut w, headers);
    }

    fn start_request_body(&mut self, response: &mut dyn ServerWriter) {
        let mut w = self.writer(response);
        self.inner.start_request_body(&mut w);
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, data: &[u8]) {
        let mut w = self.writer(response);
        self.inner.request_body_content(&mut w, data);
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
        let mut w = self.writer(response);
        self.inner.end_request_body(&mut w);
    }

    fn request_trailers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        let mut w = self.writer(response);
        self.inner.request_trailers(&mut w, headers);
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        let mut w = self.writer(response);
        self.inner.request_complete(&mut w);
    }
}
