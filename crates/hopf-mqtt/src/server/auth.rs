// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Enhanced AUTH (MQTT 5.0 §4.12) — multi-step authentication exchange.
//!
//! When CONNECT carries Authentication Method, the server drives a SASL-shaped
//! exchange via AUTH packets before CONNACK. Re-AUTH after a session is
//! established is also supported when credentials are configured. AUTH without
//! a configured method / exchange is rejected clearly (not a silent no-op).

use std::sync::Arc;

use hopf_auth::{
    create_server, SaslMechanism, SaslServer, SaslServerOptions, SaslServerStep,
};
use hopf_core::Endpoint;

use crate::codec::packet::reason;
use crate::codec::properties::property;
use crate::codec::{encode, Properties, ProtocolVersion};
use crate::server::control::MqttControlHandler;

/// In-progress enhanced AUTH exchange (between CONNECT and CONNACK, or re-AUTH).
pub(crate) struct PendingAuth {
    pub(crate) server: Box<dyn SaslServer>,
    pub(crate) method: String,
    /// When true, success yields CONNACK via [`finish_connect_after_auth`].
    pub(crate) for_connect: bool,
    pub(crate) version: ProtocolVersion,
    pub(crate) pending_connect: Option<PendingConnectAuth>,
}

/// CONNECT fields held until enhanced AUTH completes.
pub(crate) struct PendingConnectAuth {
    pub(crate) client_id: String,
    pub(crate) clean_session: bool,
    pub(crate) keep_alive_raw: u16,
    pub(crate) will: Option<crate::codec::packet::Will>,
    pub(crate) receive_maximum: u16,
    pub(crate) session_expiry_secs: u32,
    pub(crate) client_topic_alias_max: u16,
}

enum AuthOutcome {
    Continue,
    Complete,
    Failure,
}

fn step_and_reply(
    endpoint: &mut dyn Endpoint,
    server: &mut dyn SaslServer,
    method: &str,
    client_data: Option<&[u8]>,
) -> AuthOutcome {
    let result = server.step(client_data);
    match result {
        SaslServerStep::Challenge(data) => {
            let mut props = Properties::new();
            props.set_utf8(property::AUTHENTICATION_METHOD, method);
            if !data.is_empty() {
                props.set_binary(property::AUTHENTICATION_DATA, data);
            }
            endpoint.send(&encode::encode_auth(reason::CONTINUE_AUTHENTICATION, &props));
            AuthOutcome::Continue
        }
        SaslServerStep::Complete { final_message, .. } => {
            if let Some(data) = final_message.filter(|d| !d.is_empty()) {
                let mut props = Properties::new();
                props.set_utf8(property::AUTHENTICATION_METHOD, method);
                props.set_binary(property::AUTHENTICATION_DATA, data);
                endpoint.send(&encode::encode_auth(reason::SUCCESS, &props));
            }
            AuthOutcome::Complete
        }
        SaslServerStep::Failure => AuthOutcome::Failure,
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

    let mut server = make_server(&method, store).ok_or(reason::BAD_AUTHENTICATION_METHOD)?;

    // Server-first mechanisms need an initial empty step.
    if server.server_first() {
        match step_and_reply(endpoint, &mut *server, &method, None) {
            AuthOutcome::Continue => {}
            AuthOutcome::Complete => return Ok(false),
            AuthOutcome::Failure => return Err(reason::NOT_AUTHORIZED),
        }
    } else if let Some(data) = packet.properties.get_binary(property::AUTHENTICATION_DATA) {
        match step_and_reply(endpoint, &mut *server, &method, Some(data)) {
            AuthOutcome::Continue => {}
            AuthOutcome::Complete => return Ok(false),
            AuthOutcome::Failure => return Err(reason::NOT_AUTHORIZED),
        }
    } else {
        // Client must send AUTH with data next (e.g. PLAIN without initial data).
        let mut props = Properties::new();
        props.set_utf8(property::AUTHENTICATION_METHOD, &method);
        endpoint.send(&encode::encode_auth(reason::CONTINUE_AUTHENTICATION, &props));
    }

    handler.pending_auth = Some(PendingAuth {
        server,
        method,
        for_connect: true,
        version: packet.version,
        pending_connect: Some(PendingConnectAuth {
            client_id: client_id.to_string(),
            clean_session: packet.clean_session,
            keep_alive_raw: packet.keep_alive,
            will: packet.will.clone(),
            receive_maximum,
            session_expiry_secs,
            client_topic_alias_max,
        }),
    });
    Ok(true)
}

/// Handle an inbound AUTH packet (continuation or re-AUTH).
pub(crate) fn handle_auth_packet(
    handler: &mut MqttControlHandler,
    endpoint: &mut dyn Endpoint,
    properties: Properties,
) {
    if let Some(mut pending) = handler.pending_auth.take() {
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
        match step_and_reply(endpoint, &mut *pending.server, &pending.method, data) {
            AuthOutcome::Continue => {
                handler.pending_auth = Some(pending);
            }
            AuthOutcome::Complete => {
                handler.record_auth(true);
                if pending.for_connect {
                    if let Some(pc) = pending.pending_connect {
                        crate::server::control::finish_connect_after_auth(handler, endpoint, pc);
                    }
                }
            }
            AuthOutcome::Failure => {
                handler.record_auth(false);
                if pending.for_connect {
                    endpoint.send(&encode::encode_connack(
                        false,
                        reason::NOT_AUTHORIZED,
                        &Properties::new(),
                        pending.version,
                    ));
                } else {
                    endpoint.send(&encode::encode_disconnect(
                        reason::NOT_AUTHORIZED,
                        &Properties::new(),
                        pending.version,
                    ));
                }
                endpoint.close();
            }
        }
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

    let Some(mut server) = make_server(&method, store) else {
        endpoint.send(&encode::encode_disconnect(
            reason::BAD_AUTHENTICATION_METHOD,
            &Properties::new(),
            version,
        ));
        endpoint.close();
        return;
    };

    let data = properties.get_binary(property::AUTHENTICATION_DATA);
    match step_and_reply(endpoint, &mut *server, &method, data) {
        AuthOutcome::Continue => {
            handler.pending_auth = Some(PendingAuth {
                server,
                method,
                for_connect: false,
                version,
                pending_connect: None,
            });
        }
        AuthOutcome::Complete => handler.record_auth(true),
        AuthOutcome::Failure => {
            handler.record_auth(false);
            endpoint.send(&encode::encode_disconnect(
                reason::NOT_AUTHORIZED,
                &Properties::new(),
                version,
            ));
            endpoint.close();
        }
    }
}
