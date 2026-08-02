// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LDAPv3 client [`ProtocolHandler`](hopf_core::ProtocolHandler).

use std::collections::HashMap;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, StartTlsError};

use crate::asn1::{Asn1Element, Asn1Error, Asn1Type, BerDecoder};

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
        if let Err(e) = self.decoder.receive(data) {
            *data = &[];
            self.deliver_ready_err(LdapError::Asn1(e));
            endpoint.close();
            return;
        }
        *data = &[];
        loop {
            match self.decoder.next() {
                Some(msg) => {
                    if let Err(e) = self.process_message(endpoint, msg) {
                        self.deliver_ready_err(LdapError::Asn1(e));
                        endpoint.close();
                        return;
                    }
                }
                None => break,
            }
        }
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
