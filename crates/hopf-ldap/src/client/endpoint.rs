// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LDAPv3 client [`ProtocolHandler`](hopf_core::ProtocolHandler).

use std::collections::HashMap;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, StartTlsError};

use hopf_core::asn1::BerEventSink;

use crate::{Asn1Element, Asn1Error, Asn1Type, BerDecoder};

use super::session::{LdapSession, LdapShared, PendingOp, ReadyCallback, StartTlsCallback};
use super::types::{
    BindResult, LdapError, LdapResultCode, SearchDone, SearchEntry, APP_BIND_RESPONSE,
    APP_EXTENDED_RESPONSE, APP_SEARCH_RESULT_DONE, APP_SEARCH_RESULT_ENTRY,
    APP_SEARCH_RESULT_REFERENCE, CTX_REFERRAL,
};

/// Reactor-side LDAP client endpoint.
pub(crate) struct LdapEndpoint {
    shared: Arc<LdapShared>,
    on_ready: Arc<Mutex<Option<ReadyCallback>>>,
    decoder: BerDecoder,
    /// LDAPS: defer ready until [`security_established`](ProtocolHandler::security_established).
    implicit_tls_pending: bool,
    /// STARTTLS: callback waiting for handshake after ExtendedResponse success.
    awaiting_starttls: Option<StartTlsCallback>,
}

impl LdapEndpoint {
    pub(crate) fn new(
        shared: Arc<LdapShared>,
        on_ready: Arc<Mutex<Option<ReadyCallback>>>,
        implicit_tls: bool,
    ) -> Self {
        Self {
            shared,
            on_ready,
            decoder: BerDecoder::new(),
            implicit_tls_pending: implicit_tls,
            awaiting_starttls: None,
        }
    }

    fn deliver_ready(&mut self) {
        if self
            .shared
            .ready_delivered
            .swap(true, Ordering::AcqRel)
        {
            return;
        }
        let cb = self
            .on_ready
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(cb) = cb {
            cb(Ok(LdapSession {
                shared: Arc::clone(&self.shared),
            }));
        }
    }

    fn deliver_ready_err(&mut self, err: LdapError) {
        if let Some(cb) = self.awaiting_starttls.take() {
            cb(Err(err.clone_compat()));
        }
        if self
            .shared
            .ready_delivered
            .swap(true, Ordering::AcqRel)
        {
            self.shared.fail_all_pending(err);
            return;
        }
        let cb = self
            .on_ready
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(cb) = cb {
            cb(Err(err));
        } else {
            self.shared.fail_all_pending(err);
        }
    }

    fn process_message(
        &mut self,
        endpoint: &mut dyn Endpoint,
        message: Asn1Element,
    ) -> Result<(), Asn1Error> {
        if message.tag() != Asn1Type::SEQUENCE {
            return Err(Asn1Error::new(format!(
                "Expected SEQUENCE, got {}",
                Asn1Type::tag_name(message.tag())
            )));
        }
        if message.child_count() < 2 {
            return Err(Asn1Error::new("Invalid LDAP message structure"));
        }
        let message_id = message.child(0).as_i32()?;
        let protocol_op = message.child(1);
        let tag = protocol_op.tag();
        let tag_number = Asn1Type::tag_number(tag);

        if message_id == 0 {
            self.deliver_ready_err(LdapError::Protocol(
                "unsolicited notification from server".into(),
            ));
            self.shared.mark_closed();
            return Ok(());
        }

        match tag_number {
            n if n == APP_BIND_RESPONSE => self.handle_bind_response(message_id, protocol_op)?,
            n if n == APP_SEARCH_RESULT_ENTRY => {
                self.handle_search_entry(message_id, protocol_op)?;
            }
            n if n == APP_SEARCH_RESULT_DONE => {
                self.handle_search_done(message_id, protocol_op)?;
            }
            n if n == APP_SEARCH_RESULT_REFERENCE => {
                self.handle_search_reference(message_id, protocol_op)?;
            }
            n if n == APP_EXTENDED_RESPONSE => {
                self.handle_extended_response(endpoint, message_id, protocol_op)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn parse_result(
        element: &Asn1Element,
    ) -> Result<(LdapResultCode, String, String, Vec<String>), Asn1Error> {
        if element.child_count() < 3 {
            return Err(Asn1Error::new("Invalid LDAPResult structure"));
        }
        let code = LdapResultCode::from_code(element.child(0).as_i32()?);
        let matched_dn = element.child(1).as_string().unwrap_or_default();
        let diagnostic = element.child(2).as_string().unwrap_or_default();
        let mut referrals = Vec::new();
        for i in 3..element.child_count() {
            let child = element.child(i);
            if Asn1Type::tag_number(child.tag()) == CTX_REFERRAL && child.is_constructed() {
                for j in 0..child.child_count() {
                    if let Some(url) = child.child(j).as_string() {
                        if !url.is_empty() {
                            referrals.push(url);
                        }
                    }
                }
            }
        }
        Ok((code, matched_dn, diagnostic, referrals))
    }

    fn handle_bind_response(
        &mut self,
        message_id: i32,
        element: &Asn1Element,
    ) -> Result<(), Asn1Error> {
        let (code, matched_dn, diagnostic, referrals) = Self::parse_result(element)?;
        let op = self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&message_id);
        if let Some(PendingOp::Bind(cb)) = op {
            let result = BindResult {
                success: code.is_success(),
                result_code: code,
                matched_dn: if matched_dn.is_empty() {
                    None
                } else {
                    Some(matched_dn)
                },
                diagnostic: if diagnostic.is_empty() {
                    None
                } else {
                    Some(diagnostic)
                },
                referrals,
            };
            cb(Ok(result));
        }
        Ok(())
    }

    fn handle_search_entry(
        &mut self,
        message_id: i32,
        element: &Asn1Element,
    ) -> Result<(), Asn1Error> {
        if element.child_count() < 2 {
            return Err(Asn1Error::new("Invalid SearchResultEntry structure"));
        }
        let dn = element.child(0).as_string().unwrap_or_default();
        let mut attributes: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        let attr_list = element.child(1);
        for i in 0..attr_list.child_count() {
            let attr = attr_list.child(i);
            if attr.child_count() < 1 {
                continue;
            }
            let name = attr.child(0).as_string().unwrap_or_default();
            let mut values = Vec::new();
            if attr.child_count() > 1 {
                let set = attr.child(1);
                for j in 0..set.child_count() {
                    if let Some(v) = set.child(j).as_octet_string() {
                        values.push(v.to_vec());
                    }
                }
            }
            attributes.insert(name, values);
        }
        let entry = SearchEntry { dn, attributes };

        let mut pending = self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(PendingOp::Search { on_entry, .. }) = pending.get_mut(&message_id) {
            on_entry(entry);
        }
        Ok(())
    }

    fn handle_search_reference(
        &mut self,
        message_id: i32,
        element: &Asn1Element,
    ) -> Result<(), Asn1Error> {
        let mut pending = self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(PendingOp::Search { referrals, .. }) = pending.get_mut(&message_id) {
            for i in 0..element.child_count() {
                if let Some(url) = element.child(i).as_string() {
                    if !url.is_empty() {
                        referrals.push(url);
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_search_done(
        &mut self,
        message_id: i32,
        element: &Asn1Element,
    ) -> Result<(), Asn1Error> {
        let (code, _, _, mut result_referrals) = Self::parse_result(element)?;
        let op = self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&message_id);
        if let Some(PendingOp::Search {
            on_done,
            mut referrals,
            ..
        }) = op
        {
            referrals.append(&mut result_referrals);
            let done = SearchDone {
                result_code: code,
                referrals,
            };
            if code.is_success()
                || matches!(
                    code,
                    LdapResultCode::Referral
                        | LdapResultCode::NoSuchObject
                        | LdapResultCode::SizeLimitExceeded
                )
            {
                // Deliver Ok so callers can inspect referrals / soft codes.
                on_done(Ok(done));
            } else {
                on_done(Err(LdapError::SearchFailed(code)));
            }
        }
        Ok(())
    }

    fn handle_extended_response(
        &mut self,
        endpoint: &mut dyn Endpoint,
        message_id: i32,
        element: &Asn1Element,
    ) -> Result<(), Asn1Error> {
        let (code, _, _, _) = Self::parse_result(element)?;
        let op = self
            .shared
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&message_id);
        if let Some(PendingOp::StartTls(cb)) = op {
            if !code.is_success() {
                cb(Err(LdapError::StartTlsFailed(code)));
                return Ok(());
            }
            let Some((connector, sni)) = self.shared.starttls.clone() else {
                cb(Err(LdapError::Config(
                    "STARTTLS not configured on this session".into(),
                )));
                return Ok(());
            };
            match endpoint.start_client_tls(connector, &sni) {
                Ok(()) => {
                    self.awaiting_starttls = Some(cb);
                }
                Err(StartTlsError::AlreadySecure) => {
                    // Already TLS — treat as success.
                    cb(Ok(()));
                }
                Err(e) => {
                    cb(Err(LdapError::Io(io::Error::new(
                        io::ErrorKind::Other,
                        e.to_string(),
                    ))));
                }
            }
        }
        Ok(())
    }
}

/// Clone helper for error fan-out (LdapError is not Clone — rebuild common cases).
trait ErrCloneCompat {
    fn clone_compat(&self) -> Self;
}

impl ErrCloneCompat for LdapError {
    fn clone_compat(&self) -> Self {
        match self {
            Self::Io(e) => Self::Io(io::Error::new(e.kind(), e.to_string())),
            Self::Asn1(e) => Self::Asn1(Asn1Error::new(e.to_string())),
            Self::Protocol(m) => Self::Protocol(m.clone()),
            Self::Timeout => Self::Timeout,
            Self::Closed => Self::Closed,
            Self::BindFailed(c) => Self::BindFailed(*c),
            Self::SearchFailed(c) => Self::SearchFailed(*c),
            Self::StartTlsFailed(c) => Self::StartTlsFailed(*c),
            Self::Referral(m) => Self::Referral(m.clone()),
            Self::Config(m) => Self::Config(m.clone()),
        }
    }
}

/// Adapts one `receive()` call's worth of decoded elements to
/// `LdapEndpoint::process_message` — holds `&mut LdapEndpoint` (with its own
/// `decoder` field temporarily moved out by the caller) alongside the live
/// `&mut dyn Endpoint`, since `process_message` needs both (e.g. to trigger
/// a STARTTLS upgrade from an ExtendedResponse). `failed` stops processing
/// further elements once one has already closed the connection, mirroring
/// how `H2FrameHandler::frame_error` implementations stop after the first
/// fatal error in one `push`/`drain` call.
struct MessageSink<'a> {
    inner: &'a mut LdapEndpoint,
    endpoint: &'a mut dyn Endpoint,
    failed: bool,
}

impl BerEventSink for MessageSink<'_> {
    fn element(&mut self, element: Asn1Element) {
        if self.failed {
            return;
        }
        if let Err(e) = self.inner.process_message(self.endpoint, element) {
            self.inner.deliver_ready_err(LdapError::Asn1(e));
            self.endpoint.close();
            self.failed = true;
        }
    }

    fn decode_error(&mut self, err: Asn1Error) {
        if self.failed {
            return;
        }
        self.inner.deliver_ready_err(LdapError::Asn1(err));
        self.endpoint.close();
        self.failed = true;
    }
}

impl ProtocolHandler for LdapEndpoint {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        *self
            .shared
            .conn
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(endpoint.handle());
        if self.implicit_tls_pending {
            return;
        }
        self.deliver_ready();
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        // Standard push-parser shape (see `hopf_core::asn1::BerDecoder::push`
        // / `hopf_http::h2::H2Parser::push`): take the decoder out so the
        // sink adapter can hold both `&mut self` (minus its own `decoder`
        // field) and `&mut dyn Endpoint` at once, push, then restore it.
        let mut decoder = std::mem::take(&mut self.decoder);
        let mut sink = MessageSink { inner: self, endpoint, failed: false };
        decoder.push(data, &mut sink);
        *data = &[];
        self.decoder = decoder;
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.shared.closed.store(true, Ordering::Release);
        if let Some(cb) = self.awaiting_starttls.take() {
            cb(Err(LdapError::Closed));
        }
        if !self.shared.ready_delivered.load(Ordering::Acquire) {
            self.deliver_ready_err(LdapError::Closed);
        } else {
            self.shared.fail_all_pending(LdapError::Closed);
        }
    }

    fn security_established(&mut self, _endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {
        if let Some(cb) = self.awaiting_starttls.take() {
            cb(Ok(()));
        }
        if self.implicit_tls_pending {
            self.implicit_tls_pending = false;
            self.deliver_ready();
        }
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error) {
        let ldap_err = if err.kind() == io::ErrorKind::TimedOut {
            LdapError::Timeout
        } else {
            LdapError::Io(io::Error::new(err.kind(), err.to_string()))
        };
        self.deliver_ready_err(ldap_err);
        endpoint.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::{ConnHandle, PeerAddr, TimerHandle, WriteReadyCallback};
    use std::time::Duration;

    use crate::BerEncoder;

    struct FakeEp {
        closed: bool,
        secure: SecurityInfo,
        handle: ConnHandle,
    }

    impl FakeEp {
        fn new() -> Self {
            Self {
                closed: false,
                secure: SecurityInfo::plaintext(),
                handle: ConnHandle::from_execute(Arc::new(|task| task())),
            }
        }
    }

    impl Endpoint for FakeEp {
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
        fn local_addr(&self) -> io::Result<PeerAddr> {
            "127.0.0.1:0".parse::<std::net::SocketAddr>().map(PeerAddr::Inet).map_err(io::Error::other)
        }
        fn remote_addr(&self) -> io::Result<PeerAddr> {
            self.local_addr()
        }
        fn security_info(&self) -> &SecurityInfo {
            &self.secure
        }
        fn start_tls(&mut self) -> Result<(), StartTlsError> {
            Err(StartTlsError::Unsupported)
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _cb: Option<WriteReadyCallback>) {}
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn schedule_timer(&self, _delay: Duration, _cb: Box<dyn FnOnce() + Send>) -> TimerHandle {
            TimerHandle::from_cancel(|| {})
        }
        fn handle(&self) -> ConnHandle {
            self.handle.clone()
        }
    }

    fn bind_response_wire(message_id: i32, result_code: i32) -> Vec<u8> {
        let mut encoder = BerEncoder::new();
        encoder.begin_sequence();
        encoder.write_integer_i32(message_id);
        encoder.begin_application(APP_BIND_RESPONSE, true);
        encoder.write_enumerated(result_code);
        encoder.write_octet_string_str("");
        encoder.write_octet_string_str("");
        encoder.end_application();
        encoder.end_sequence();
        encoder.to_bytes()
    }

    /// Exercises the full `receive()` pipeline this module's push-parser
    /// reshape rewired: `mem::take` the decoder out, drive it via
    /// `BerDecoder::push`, dispatch each decoded `LDAPMessage` through
    /// `MessageSink::element` → `process_message` → `handle_bind_response`,
    /// then restore the decoder. Proves it's not just type-checking —
    /// registered per-message-id callbacks actually fire with the right
    /// results, for two messages arriving in one `receive()` call.
    #[test]
    fn receive_dispatches_each_decoded_message_to_its_pending_callback() {
        let shared = Arc::new(LdapShared::new(None));
        let on_ready: Arc<Mutex<Option<ReadyCallback>>> = Arc::new(Mutex::new(Some(Box::new(|_| {}))));
        let mut ep = LdapEndpoint::new(Arc::clone(&shared), on_ready, false);
        let mut fake = FakeEp::new();
        ep.connected(&mut fake);

        let result1: Arc<Mutex<Option<Result<BindResult, LdapError>>>> = Arc::new(Mutex::new(None));
        let result2: Arc<Mutex<Option<Result<BindResult, LdapError>>>> = Arc::new(Mutex::new(None));
        {
            let mut pending = shared.pending.lock().unwrap();
            let r1 = Arc::clone(&result1);
            pending.insert(1, PendingOp::Bind(Box::new(move |r| *r1.lock().unwrap() = Some(r))));
            let r2 = Arc::clone(&result2);
            pending.insert(2, PendingOp::Bind(Box::new(move |r| *r2.lock().unwrap() = Some(r))));
        }

        let mut wire = bind_response_wire(1, 0); // success
        wire.extend(bind_response_wire(2, 49)); // invalidCredentials
        ep.receive(&mut fake, &mut wire.as_slice());

        let got1 = result1.lock().unwrap().take().expect("message 1 dispatched");
        let bind1 = got1.expect("message 1 decoded without error");
        assert!(bind1.success);
        assert_eq!(bind1.result_code, LdapResultCode::Success);

        let got2 = result2.lock().unwrap().take().expect("message 2 dispatched");
        let bind2 = got2.expect("message 2 decoded without error");
        assert!(!bind2.success);
        assert_eq!(bind2.result_code, LdapResultCode::InvalidCredentials);

        assert!(!fake.closed, "well-formed messages must not close the connection");
        assert!(shared.pending.lock().unwrap().is_empty(), "both pending ops must be consumed");
    }

    /// Malformed input must reach `MessageSink::decode_error` and close the
    /// connection — not silently stall (the pre-reshape code did this via
    /// `receive()`'s own `Result`; this proves the callback-based
    /// `BerEventSink::decode_error` path reaches the same outcome).
    #[test]
    fn receive_closes_connection_on_malformed_ber() {
        let shared = Arc::new(LdapShared::new(None));
        let on_ready: Arc<Mutex<Option<ReadyCallback>>> = Arc::new(Mutex::new(Some(Box::new(|_| {}))));
        let mut ep = LdapEndpoint::new(shared, on_ready, false);
        let mut fake = FakeEp::new();
        ep.connected(&mut fake);

        let wire: Vec<u8> = vec![0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00]; // indefinite length
        ep.receive(&mut fake, &mut wire.as_slice());

        assert!(fake.closed);
    }
}
