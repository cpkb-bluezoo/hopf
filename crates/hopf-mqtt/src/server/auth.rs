// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Enhanced AUTH (MQTT 5.0 §4.12) — multi-step authentication exchange.
//!
//! When CONNECT carries Authentication Method, the server drives a SASL-shaped
//! exchange via AUTH packets before CONNACK. Re-AUTH after a session is
//! established is also supported when credentials are configured. AUTH without
//! a configured method / exchange is rejected clearly (not a silent no-op).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use hopf_auth::{
    create_server, SaslMechanism, SaslServer, SaslServerOptions, SaslServerStep,
};
use hopf_core::{Endpoint, StorageError};

use crate::codec::packet::reason;
use crate::codec::properties::property;
use crate::codec::{encode, Properties, ProtocolVersion};
use crate::server::control::{AuthStepOutcome, MqttControlHandler};

/// In-progress enhanced AUTH exchange (between CONNECT and CONNACK, or re-AUTH).
pub(crate) struct PendingAuth {
    pub(crate) server: Box<dyn SaslServer>,
    pub(crate) method: String,
    /// When true, success yields CONNACK via [`finish_connect_after_auth`].
    pub(crate) for_connect: bool,
    pub(crate) version: ProtocolVersion,
    pub(crate) pending_connect: Option<PendingConnectAuth>,
}

/// CONNECT fields held until enhanced AUTH (or, issue #210, an offloaded
/// plain-CONNECT `authorize()` call) completes.
pub(crate) struct PendingConnectAuth {
    pub(crate) client_id: String,
    pub(crate) clean_session: bool,
    pub(crate) keep_alive_raw: u16,
    pub(crate) will: Option<crate::codec::packet::Will>,
    pub(crate) receive_maximum: u16,
    pub(crate) session_expiry_secs: u32,
    pub(crate) client_topic_alias_max: u16,
    /// Enhanced AUTH is MQTT5-only, so `finish_connect_after_auth` used to
    /// hardcode `ProtocolVersion::V5` — issue #210's plain-CONNECT offload
    /// reuses the same continuation for v3.1.1 connections too, so the
    /// version now travels with the rest of the pending state instead.
    pub(crate) version: ProtocolVersion,
}

/// Run one SASL step off the reactor thread (issue #181 — `SaslServer::step`
/// can block for LDAP/PAM-backed stores). The result is applied later by
/// [`sync_pending_auth_check`], once back on the reactor — this call site
/// used to do the step and send the resulting reply/challenge inline
/// (`step_and_reply`); now the two are split across the async boundary, so
/// every bit of context needed to resume (which of the CONNECT-initial /
/// continuation / re-AUTH branches, and the pending CONNECT fields for the
/// first of those) travels in [`AuthStepOutcome`] instead of living on the
/// call stack.
fn offload_step(
    handler: &mut MqttControlHandler,
    endpoint: &mut dyn Endpoint,
    mut server: Box<dyn SaslServer>,
    client_data: Option<&[u8]>,
    method: String,
    version: ProtocolVersion,
    for_connect: bool,
    pending_connect: Option<PendingConnectAuth>,
) {
    let Some(handle) = handler.control_handle.clone() else {
        endpoint.send(&encode::encode_disconnect(reason::UNSPECIFIED_ERROR, &Properties::new(), version));
        endpoint.close();
        return;
    };
    let client_data = client_data.map(<[u8]>::to_vec);
    let pending = Arc::clone(&handler.pending_auth_check);
    let busy = Arc::clone(&handler.busy);
    handler.busy.store(true, Ordering::Relaxed);
    handler.runtime.storage().submit_on(
        handle.clone(),
        move || {
            // `step()` is callback-based (may complete inline, or hand off
            // to e.g. an OAUTHBEARER introspection transport); bridge back
            // to `submit_on`'s synchronous-`op` contract. This closure
            // already runs on a storage-pool thread, never the reactor, so
            // blocking here is exactly what `StorageExecutor` is for
            // (issue #182).
            let (tx, rx) = std::sync::mpsc::channel();
            server.step(client_data.as_deref(), Box::new(move |step| {
                let _ = tx.send(step);
            }));
            let step = rx.recv().map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
                "SaslServer::step callback dropped without completing".into()
            })?;
            Ok((server, step))
        },
        move |result: Result<(Box<dyn SaslServer>, SaslServerStep), StorageError>| {
            let result = result.map_err(|e| e.to_string());
            *pending.lock().unwrap() = Some(AuthStepOutcome {
                result,
                method,
                version,
                for_connect,
                pending_connect,
            });
            handle.with_endpoint(move |ep| {
                busy.store(false, Ordering::Relaxed);
                // Nothing has been sent to the client yet at this point —
                // the reply depends entirely on `sync_pending_auth_check`,
                // which needs `&mut MqttControlHandler` and so can't run
                // from here. The client is waiting on us, not about to
                // send more input, so nothing else would trigger another
                // `receive()` call; `poke_handler` forces one.
                ep.poke_handler();
            });
        },
    );
}

/// Apply the outcome of an offloaded SASL step, once `offload_step`'s
/// `submit_on` callback has stashed one — see [`AuthStepOutcome`]. Called
/// from `MqttControlHandler::receive` before every packet parse, mirroring
/// the synchronous reply/state logic `step_and_reply` plus each of its call
/// sites used to do inline.
pub(crate) fn sync_pending_auth_check(handler: &mut MqttControlHandler, endpoint: &mut dyn Endpoint) {
    let Some(AuthStepOutcome {
        result,
        method,
        version,
        for_connect,
        pending_connect,
    }) = handler.pending_auth_check.lock().unwrap().take()
    else {
        return;
    };
    let (server, step) = match result {
        Ok(ok) => ok,
        Err(_e) => {
            handler.record_auth(false);
            if for_connect {
                endpoint.send(&encode::encode_connack(
                    false,
                    reason::SERVER_UNAVAILABLE,
                    &Properties::new(),
                    version,
                ));
            } else {
                endpoint.send(&encode::encode_disconnect(
                    reason::SERVER_UNAVAILABLE,
                    &Properties::new(),
                    version,
                ));
            }
            endpoint.close();
            return;
        }
    };
    match step {
        SaslServerStep::Challenge(data) => {
            let mut props = Properties::new();
            props.set_utf8(property::AUTHENTICATION_METHOD, &method);
            if !data.is_empty() {
                props.set_binary(property::AUTHENTICATION_DATA, data);
            }
            endpoint.send(&encode::encode_auth(reason::CONTINUE_AUTHENTICATION, &props));
            handler.pending_auth = Some(PendingAuth {
                server,
                method,
                for_connect,
                version,
                pending_connect,
            });
        }
        SaslServerStep::Complete { final_message, .. } => {
            if let Some(data) = final_message.filter(|d| !d.is_empty()) {
                let mut props = Properties::new();
                props.set_utf8(property::AUTHENTICATION_METHOD, &method);
                props.set_binary(property::AUTHENTICATION_DATA, data);
                endpoint.send(&encode::encode_auth(reason::SUCCESS, &props));
            }
            handler.record_auth(true);
            if for_connect {
                if let Some(pc) = pending_connect {
                    crate::server::control::finish_connect_after_auth(handler, endpoint, pc);
                }
            }
        }
        SaslServerStep::Failure => {
            handler.record_auth(false);
            if for_connect {
                endpoint.send(&encode::encode_connack(
                    false,
                    reason::NOT_AUTHORIZED,
                    &Properties::new(),
                    version,
                ));
            } else {
                endpoint.send(&encode::encode_disconnect(
                    reason::NOT_AUTHORIZED,
                    &Properties::new(),
                    version,
                ));
            }
            endpoint.close();
        }
    }
}

fn make_server(
    method: &str,
    store: Arc<dyn hopf_auth::CredentialStore>,
) -> Option<Box<dyn SaslServer>> {
    let mech = SaslMechanism::from_name(method)?;
    Some(create_server(
        mech,
        store,
        SaslServerOptions {
            hostname: "localhost".into(),
            realm: "hopf-mqtt".into(),
            peer_certificate: None,
            channel_binding: None,
        },
    ))
}

/// Start enhanced AUTH for CONNECT when Authentication Method is present.
///
/// Returns `Ok(true)` if AUTH was started (caller must not send CONNACK yet),
/// `Ok(false)` if no method was requested, or `Err(reason)` for CONNACK refusal.
pub(crate) fn maybe_start_connect_auth(
    handler: &mut MqttControlHandler,
    endpoint: &mut dyn Endpoint,
    packet: &crate::codec::packet::ConnectPacket,
    client_id: &str,
    receive_maximum: u16,
    session_expiry_secs: u32,
    client_topic_alias_max: u16,
) -> Result<bool, u8> {
    let Some(method) = packet
        .properties
        .get_utf8(property::AUTHENTICATION_METHOD)
        .map(|s| s.to_string())
    else {
        return Ok(false);
    };

    if !packet.version.is_v5() {
        return Err(reason::PROTOCOL_ERROR);
    }

    let Some(store) = handler.config.credentials.clone() else {
        return Err(reason::BAD_AUTHENTICATION_METHOD);
    };

    let server = make_server(&method, store).ok_or(reason::BAD_AUTHENTICATION_METHOD)?;

    let pending_connect = PendingConnectAuth {
        client_id: client_id.to_string(),
        clean_session: packet.clean_session,
        keep_alive_raw: packet.keep_alive,
        will: packet.will.clone(),
        receive_maximum,
        session_expiry_secs,
        client_topic_alias_max,
        version: packet.version,
    };

    // Server-first mechanisms need an initial empty step.
    if server.server_first() {
        offload_step(handler, endpoint, server, None, method, packet.version, true, Some(pending_connect));
    } else if let Some(data) = packet.properties.get_binary(property::AUTHENTICATION_DATA) {
        let data = data.to_vec();
        offload_step(handler, endpoint, server, Some(&data), method, packet.version, true, Some(pending_connect));
    } else {
        // Client must send AUTH with data next (e.g. PLAIN without initial
        // data) — nothing to step yet, so no offload needed here; just
        // prompt and stash the server for the continuation to offload.
        let mut props = Properties::new();
        props.set_utf8(property::AUTHENTICATION_METHOD, &method);
        endpoint.send(&encode::encode_auth(reason::CONTINUE_AUTHENTICATION, &props));
        handler.pending_auth = Some(PendingAuth {
            server,
            method,
            for_connect: true,
            version: packet.version,
            pending_connect: Some(pending_connect),
        });
    }
    Ok(true)
}

/// Handle an inbound AUTH packet (continuation or re-AUTH).
pub(crate) fn handle_auth_packet(
    handler: &mut MqttControlHandler,
    endpoint: &mut dyn Endpoint,
    properties: Properties,
) {
    if let Some(pending) = handler.pending_auth.take() {
        if let Some(method) = properties.get_utf8(property::AUTHENTICATION_METHOD) {
            if method != pending.method {
                endpoint.send(&encode::encode_disconnect(
                    reason::BAD_AUTHENTICATION_METHOD,
                    &Properties::new(),
                    pending.version,
                ));
                endpoint.close();
                return;
            }
        }
        let data = properties.get_binary(property::AUTHENTICATION_DATA);
        offload_step(
            handler,
            endpoint,
            pending.server,
            data,
            pending.method,
            pending.version,
            pending.for_connect,
            pending.pending_connect,
        );
        return;
    }

    // Re-AUTH after an established session.
    let version = handler.session_version().unwrap_or(ProtocolVersion::V5);
    let Some(method) = properties
        .get_utf8(property::AUTHENTICATION_METHOD)
        .map(|s| s.to_string())
    else {
        endpoint.send(&encode::encode_disconnect(
            reason::PROTOCOL_ERROR,
            &Properties::new(),
            version,
        ));
        endpoint.close();
        return;
    };

    let Some(store) = handler.config.credentials.clone() else {
        endpoint.send(&encode::encode_disconnect(
            reason::BAD_AUTHENTICATION_METHOD,
            &Properties::new(),
            version,
        ));
        endpoint.close();
        return;
    };

    let Some(server) = make_server(&method, store) else {
        endpoint.send(&encode::encode_disconnect(
            reason::BAD_AUTHENTICATION_METHOD,
            &Properties::new(),
            version,
        ));
        endpoint.close();
        return;
    };

    let data = properties.get_binary(property::AUTHENTICATION_DATA);
    offload_step(handler, endpoint, server, data, method, version, false, None);
}
