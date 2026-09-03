// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`ServerHandlerFactory`] that accepts RFC 9484 CONNECT-IP requests on
//! H1/H2/H3 and hands the accepted tunnel to the application via
//! [`crate::ConnectIpHandlerFactory`].

use std::sync::Arc;

use hopf_http::capsule::capsule_protocol_enabled;
use hopf_http::{Headers, ServerHandler, ServerHandlerFactory, ServerWriter};

use crate::accept::{accept_headers, is_extended_connect, is_h1_upgrade, send_error};
use crate::ip_policy::ConnectIpPolicy;
use crate::ip_relay::{ConnectIpHandlerFactory, ConnectIpRelay};
use crate::ip_target;

const PROTOCOL: &str = "connect-ip";

/// Builds per-request [`ConnectIpRequestHandler`]s.
///
/// Needs a [`ConnectIpHandlerFactory`] (to build the application's
/// per-tunnel forwarding handler — see that trait's own docs for why this
/// crate has no built-in notion of where a decoded packet goes) and a
/// [`ConnectIpPolicy`] (to approve or deny each request's target scope
/// before any tunnel opens).
pub struct ConnectIpFactory {
    app: Arc<dyn ConnectIpHandlerFactory>,
    policy: Arc<dyn ConnectIpPolicy>,
}

impl ConnectIpFactory {
    /// `policy` has no permissive default anywhere in this crate — pass
    /// one that actually decides which target scopes to allow.
    pub fn new(app: Arc<dyn ConnectIpHandlerFactory>, policy: Arc<dyn ConnectIpPolicy>) -> Self {
        Self { app, policy }
    }
}

impl ServerHandlerFactory for ConnectIpFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(ConnectIpRequestHandler {
            app: Arc::clone(&self.app),
            policy: Arc::clone(&self.policy),
        })
    }
}

struct ConnectIpRequestHandler {
    app: Arc<dyn ConnectIpHandlerFactory>,
    policy: Arc<dyn ConnectIpPolicy>,
}

impl ServerHandler for ConnectIpRequestHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        let extended_connect = is_extended_connect(headers, PROTOCOL);
        if !extended_connect && !is_h1_upgrade(headers, PROTOCOL) {
            send_error(response, 400, "CONNECT-IP upgrade required");
            return;
        }
        if !capsule_protocol_enabled(headers) {
            send_error(response, 400, "Capsule-Protocol required");
            return;
        }
        let Some(target) = ip_target::parse(headers.path().unwrap_or("")) else {
            send_error(response, 400, "malformed CONNECT-IP target");
            return;
        };
        if !self.policy.is_target_allowed(&target.target, &target.ipproto) {
            send_error(response, 403, "target not allowed");
            return;
        }

        // Unlike CONNECT-UDP, there's no relay resource of this crate's
        // own to set up first (no DNS lookup, no outbound socket) — the
        // application's handler is the only thing standing between here
        // and accepting, so this can install the upgrade synchronously.
        let handler = self.app.create_handler();
        let conn = response.conn_handle();
        let relay = ConnectIpRelay::accept(conn, handler);
        if !response.upgrade(accept_headers(extended_connect, PROTOCOL), Box::new(relay)) {
            send_error(response, 500, "upgrade failed");
        }
    }

    fn request_complete(&mut self, _response: &mut dyn ServerWriter) {}
}
