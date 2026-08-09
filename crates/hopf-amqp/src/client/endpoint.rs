// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `AmqpClientEndpoint` — async AMQP 0-9-1 client as a [`ProtocolHandler`].

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use hopf_auth::{create_client, SaslClient, SaslClientStep, SaslMechanism};
use hopf_core::{Endpoint, ProtocolHandler, SharedTlsConnector, TimerHandle};

use crate::codec::encode::{
    encode_content, encode_heartbeat, encode_method, encode_protocol_header,
};
use crate::codec::methods::{
    decode_ack, decode_basic_cancel, decode_connection_blocked, decode_connection_secure,
    decode_consumer_tag, decode_flow_active, decode_nack, encode_basic_ack, encode_basic_cancel,
    encode_basic_cancel_ok, encode_basic_consume, encode_basic_get, encode_basic_nack,
    encode_basic_publish, encode_basic_qos, encode_basic_recover, encode_basic_reject,
    encode_channel_flow, encode_channel_open, encode_confirm_select, encode_connection_open,
    encode_connection_secure_ok, encode_connection_start_ok, encode_exchange_declare,
    encode_exchange_delete, encode_queue_bind, encode_queue_declare, encode_queue_delete,
    encode_queue_purge, encode_queue_unbind, encode_tx_method, BasicDeliver, BasicGetOk,
    BasicReturn, CloseArgs, ConnectionStart, ConnectionTune, MethodFrame, QueueDeclareOk,
};
use crate::codec::parser::{AmqpFrameHandler, AmqpFrameParser};
use crate::codec::table::{encode_amqplain, FieldTable, FieldValue};
use crate::codec::types::{
    basic, channel as channel_ids, class, confirm, connection, exchange as exchange_ids,
    queue as queue_ids, reply, tx, DEFAULT_CHANNEL_MAX, DEFAULT_FRAME_MAX,
};
use crate::codec::{AmqpError, BasicProperties};

use super::handlers::{AmqpClientControl, AmqpClientDriver, AmqpClientHandlerFactory};

/// Marker on TimedOut errors meaning "send a heartbeat".
const HEARTBEAT_DUE: &str = "hopf-amqp-heartbeat-due";

/// Pending content after a content-bearing method (deliver / return / get-ok).
enum PendingContent {
    Deliver(BasicDeliver),
    Return(BasicReturn),
    Get(BasicGetOk),
}

/// Builder input bundled by [`super::facade::AmqpClient`].
#[derive(Clone)]
pub struct AmqpClientParams {
    /// Virtual host (default `/`).
    pub virtual_host: String,
    /// Username (default `guest`).
    pub username: String,
    /// Password (default `guest`).
    pub password: String,
    /// Forced SASL mechanism wire name (e.g. `"EXTERNAL"`); `None` means
    /// auto-negotiate PLAIN, then AMQPLAIN.
    pub mechanism: Option<String>,
    /// Client-preferred heartbeat seconds (0 = none); negotiated with broker.
    pub heartbeat: u16,
    /// Client frame_max cap (0 = accept broker).
    pub frame_max: u32,
    /// Client channel_max cap (0 = accept broker).
    pub channel_max: u16,
    /// TLS connector for AMQPS.
    pub tls_connector: Option<SharedTlsConnector>,
    /// TLS server name.
    pub tls_server_name: Option<String>,
    /// Whether TLS starts immediately.
    pub implicit_tls: bool,
    /// Handshake deadline.
    pub handshake_timeout: Duration,
    /// Heartbeat miss floor timeout.
    pub heartbeat_timeout: Duration,
}

/// Async AMQP client [`ProtocolHandler`].
pub struct AmqpClientEndpoint {
    driver: Option<Box<dyn AmqpClientDriver>>,
    parser: AmqpFrameParser,
    virtual_host: String,
    username: String,
    password: String,
    mechanism: Option<String>,
    /// SASL exchange in progress between `connection.start-ok` and the
    /// final `connection.tune` (`Some` only while a multi-step mechanism
    /// is mid-handshake).
    sasl_client: Option<Box<dyn SaslClient>>,
    preferred_heartbeat: u16,
    preferred_frame_max: u32,
    preferred_channel_max: u16,
    negotiated_frame_max: u32,
    negotiated_channel_max: u16,
    negotiated_heartbeat: u16,
    handshake_timeout: Duration,
    heartbeat_timeout: Duration,
    handshake_timer: Option<TimerHandle>,
    heartbeat_send_timer: Option<TimerHandle>,
    heartbeat_recv_timer: Option<TimerHandle>,
    open: bool,
    closed: bool,
    /// Next publisher confirm delivery tag per channel (starts at 1).
    next_publish_tag: HashMap<u16, u64>,
    pending_content: Option<PendingContent>,
    pending_props: Option<BasicProperties>,
    pending_body_len: u64,
    pending_body_received: u64,
    content_is_return: bool,
}

impl AmqpClientEndpoint {
    /// Create from factory + params.
    pub fn new(factory: &dyn AmqpClientHandlerFactory, params: AmqpClientParams) -> Self {
        Self {
            driver: Some(factory.create()),
            parser: AmqpFrameParser::new(DEFAULT_FRAME_MAX),
            virtual_host: params.virtual_host,
            username: params.username,
            password: params.password,
            mechanism: params.mechanism,
            sasl_client: None,
            preferred_heartbeat: params.heartbeat,
            preferred_frame_max: params.frame_max,
            preferred_channel_max: params.channel_max,
            negotiated_frame_max: DEFAULT_FRAME_MAX,
            negotiated_channel_max: DEFAULT_CHANNEL_MAX,
            negotiated_heartbeat: 0,
            handshake_timeout: params.handshake_timeout,
            heartbeat_timeout: params.heartbeat_timeout,
            handshake_timer: None,
            heartbeat_send_timer: None,
            heartbeat_recv_timer: None,
            open: false,
            closed: false,
            next_publish_tag: HashMap::new(),
            pending_content: None,
            pending_props: None,
            pending_body_len: 0,
            pending_body_received: 0,
            content_is_return: false,
        }
    }

    fn send_method(&mut self, endpoint: &mut dyn Endpoint, channel: u16, class_id: u16, method_id: u16, args: &[u8]) {
        endpoint.send(&encode_method(channel, class_id, method_id, args));
    }

    fn with_driver_control<F>(&mut self, endpoint: &mut dyn Endpoint, f: F)
    where
        F: FnOnce(&mut dyn AmqpClientDriver, &mut dyn AmqpClientControl),
    {
        let mut driver = match self.driver.take() {
            Some(d) => d,
            None => return,
        };
        // Safety: we re-implement Control by temporarily using self via a helper struct.
        let mut ctl = ControlAdapter {
            inner: self,
            endpoint,
        };
        f(driver.as_mut(), &mut ctl);
        self.driver = Some(driver);
    }

    fn fail_io(&mut self, endpoint: &mut dyn Endpoint, msg: &str) {
        let err = io::Error::new(io::ErrorKind::InvalidData, msg);
        if let Some(ref mut d) = self.driver {
            d.on_error(&err);
        }
        endpoint.fail(err);
    }

    fn arm_handshake_timer(&mut self, endpoint: &mut dyn Endpoint) {
        if self.handshake_timeout.is_zero() {
            return;
        }
        let handle = endpoint.handle();
        let timeout = self.handshake_timeout;
        self.handshake_timer = Some(endpoint.schedule_timer(
            timeout,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "amqp handshake timeout",
                    ));
                });
            }),
        ));
    }

    fn clear_handshake_timer(&mut self, _endpoint: &mut dyn Endpoint) {
        if let Some(t) = self.handshake_timer.take() {
            t.cancel();
        }
    }

    fn arm_heartbeat_timers(&mut self, endpoint: &mut dyn Endpoint) {
        if self.negotiated_heartbeat == 0 {
            return;
        }
        self.rearm_heartbeat_send(endpoint);
        self.rearm_heartbeat_recv(endpoint);
    }

    fn rearm_heartbeat_send(&mut self, endpoint: &mut dyn Endpoint) {
        if self.negotiated_heartbeat == 0 {
            return;
        }
        if let Some(t) = self.heartbeat_send_timer.take() {
            t.cancel();
        }
        let handle = endpoint.handle();
        let interval = Duration::from_secs(u64::from(self.negotiated_heartbeat));
        self.heartbeat_send_timer = Some(endpoint.schedule_timer(
            interval,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(io::ErrorKind::TimedOut, HEARTBEAT_DUE));
                });
            }),
        ));
    }

    fn rearm_heartbeat_recv(&mut self, endpoint: &mut dyn Endpoint) {
        if self.negotiated_heartbeat == 0 {
            return;
        }
        if let Some(t) = self.heartbeat_recv_timer.take() {
            t.cancel();
        }
        let handle = endpoint.handle();
        let interval = Duration::from_secs(u64::from(self.negotiated_heartbeat));
        let recv = interval
            .checked_mul(2)
            .unwrap_or(interval)
            .max(self.heartbeat_timeout);
        self.heartbeat_recv_timer = Some(endpoint.schedule_timer(
            recv,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "amqp heartbeat timeout",
                    ));
                });
            }),
        ));
    }

    fn handle_connection_start(&mut self, endpoint: &mut dyn Endpoint, args: &[u8]) -> Result<(), AmqpError> {
        let start = ConnectionStart::decode(args)?;
        let mechs: Vec<&str> = start.mechanisms.split_whitespace().collect();
        let mut client_props = FieldTable::new();
        client_props.insert("product".into(), FieldValue::longstr("hopf-amqp"));
        client_props.insert(
            "version".into(),
            FieldValue::longstr(env!("CARGO_PKG_VERSION")),
        );
        client_props.insert("platform".into(), FieldValue::longstr("Rust"));

        let chosen = choose_mechanism(self.mechanism.as_deref(), &mechs)?;

        let response = if chosen.eq_ignore_ascii_case("AMQPLAIN") {
            encode_amqplain(&self.username, &self.password)?
        } else {
            // AMQPLAIN aside, only PLAIN and EXTERNAL are wired through
            // hopf_auth today — anything else (a forced but unimplemented
            // mechanism, e.g. GSSAPI or DIGEST-MD5) fails clearly here
            // rather than being silently attempted.
            let mech = match chosen.to_ascii_uppercase().as_str() {
                "PLAIN" => SaslMechanism::Plain,
                "EXTERNAL" => SaslMechanism::External,
                _ => return Err(AmqpError::Malformed("unsupported SASL mechanism")),
            };
            if mech == SaslMechanism::External && !endpoint.is_secure() {
                return Err(AmqpError::Malformed("EXTERNAL requires a TLS connection"));
            }
            let mut client = create_client(mech, &self.username, &self.password, "", "amqp", None);
            let response = if client.has_initial_response() {
                match client.evaluate(None) {
                    SaslClientStep::Response(r) | SaslClientStep::Complete(r) => r,
                    SaslClientStep::Failure => {
                        return Err(AmqpError::Malformed("SASL mechanism setup failed"));
                    }
                }
            } else {
                Vec::new()
            };
            self.sasl_client = Some(client);
            response
        };

        let start_ok_args = encode_connection_start_ok(&client_props, &chosen, &response, "en_US")?;
        self.send_method(
            endpoint,
            0,
            class::CONNECTION,
            connection::START_OK,
            &start_ok_args,
        );
        Ok(())
    }

    fn handle_connection_tune(&mut self, endpoint: &mut dyn Endpoint, args: &[u8]) -> Result<(), AmqpError> {
        // The SASL exchange is over once we reach tune (regardless of how
        // many connection.secure round-trips it took).
        self.sasl_client = None;
        let tune = ConnectionTune::decode(args)?;
        let channel_max = negotiate_max_u16(tune.channel_max, self.preferred_channel_max, DEFAULT_CHANNEL_MAX);
        let frame_max = negotiate_max_u32(tune.frame_max, self.preferred_frame_max, DEFAULT_FRAME_MAX);
        let heartbeat = negotiate_heartbeat(tune.heartbeat, self.preferred_heartbeat);
        self.negotiated_channel_max = channel_max;
        self.negotiated_frame_max = frame_max;
        self.negotiated_heartbeat = heartbeat;
        self.parser.set_max_frame(frame_max);

        let ok = ConnectionTune {
            channel_max,
            frame_max,
            heartbeat,
        };
        self.send_method(endpoint, 0, class::CONNECTION, connection::TUNE_OK, &ok.encode());
        let open_args = encode_connection_open(&self.virtual_host)?;
        self.send_method(endpoint, 0, class::CONNECTION, connection::OPEN, &open_args);
        Ok(())
    }

    fn handle_method(&mut self, endpoint: &mut dyn Endpoint, frame: MethodFrame) {
        let MethodFrame {
            channel,
            class_id,
            method_id,
            args,
        } = frame;

        if class_id == class::CONNECTION {
            match method_id {
                connection::START => {
                    if let Err(e) = self.handle_connection_start(endpoint, &args) {
                        self.fail_io(endpoint, &e.to_string());
                    }
                }
                connection::TUNE => {
                    if let Err(e) = self.handle_connection_tune(endpoint, &args) {
                        self.fail_io(endpoint, &e.to_string());
                    }
                }
                connection::OPEN_OK => {
                    self.clear_handshake_timer(endpoint);
                    self.open = true;
                    self.arm_heartbeat_timers(endpoint);
                    self.with_driver_control(endpoint, |d, c| d.on_connection_open(c));
                }
                connection::CLOSE => {
                    let close = match CloseArgs::decode(&args) {
                        Ok(c) => c,
                        Err(e) => {
                            self.fail_io(endpoint, &e.to_string());
                            return;
                        }
                    };
                    self.send_method(endpoint, 0, class::CONNECTION, connection::CLOSE_OK, &[]);
                    if let Some(ref mut d) = self.driver {
                        d.on_connection_close(close.reply_code, &close.reply_text);
                    }
                    self.closed = true;
                    endpoint.close();
                }
                connection::CLOSE_OK => {
                    self.closed = true;
                    endpoint.close();
                }
                connection::SECURE => {
                    let challenge = match decode_connection_secure(&args) {
                        Ok(c) => c,
                        Err(e) => {
                            self.fail_io(endpoint, &e.to_string());
                            return;
                        }
                    };
                    let Some(mut client) = self.sasl_client.take() else {
                        self.fail_io(
                            endpoint,
                            "unexpected connection.secure (no SASL exchange in progress)",
                        );
                        return;
                    };
                    match client.evaluate(Some(&challenge)) {
                        SaslClientStep::Response(r) | SaslClientStep::Complete(r) => {
                            let ok_args = encode_connection_secure_ok(&r);
                            self.sasl_client = Some(client);
                            self.send_method(
                                endpoint,
                                0,
                                class::CONNECTION,
                                connection::SECURE_OK,
                                &ok_args,
                            );
                        }
                        SaslClientStep::Failure => {
                            self.fail_io(endpoint, "SASL mechanism rejected broker challenge");
                        }
                    }
                }
                connection::BLOCKED => match decode_connection_blocked(&args) {
                    Ok(reason) => {
                        if let Some(ref mut d) = self.driver {
                            d.on_connection_blocked(&reason);
                        }
                    }
                    Err(e) => self.fail_io(endpoint, &e.to_string()),
                },
                connection::UNBLOCKED => {
                    if let Some(ref mut d) = self.driver {
                        d.on_connection_unblocked();
                    }
                }
                _ => {}
            }
            return;
        }

        if class_id == class::CHANNEL {
            match method_id {
                channel_ids::OPEN_OK => {
                    self.with_driver_control(endpoint, |d, c| d.on_channel_open(c, channel));
                }
                channel_ids::CLOSE => {
                    let close = match CloseArgs::decode(&args) {
                        Ok(c) => c,
                        Err(e) => {
                            self.fail_io(endpoint, &e.to_string());
                            return;
                        }
                    };
                    self.send_method(endpoint, channel, class::CHANNEL, channel_ids::CLOSE_OK, &[]);
                    self.with_driver_control(endpoint, |d, c| {
                        d.on_channel_close(c, channel, close.reply_code, &close.reply_text);
                    });
                }
                channel_ids::CLOSE_OK => {
                    self.with_driver_control(endpoint, |d, c| {
                        d.on_channel_close(c, channel, reply::SUCCESS, "OK");
                    });
                }
                channel_ids::FLOW => {
                    // The protocol requires an immediate echo of flow-ok
                    // with the same active bit, regardless of what the
                    // driver decides to do about it.
                    let active = decode_flow_active(&args);
                    self.send_method(
                        endpoint,
                        channel,
                        class::CHANNEL,
                        channel_ids::FLOW_OK,
                        &encode_channel_flow(active),
                    );
                    self.with_driver_control(endpoint, |d, c| d.on_flow(c, channel, active));
                }
                channel_ids::FLOW_OK => {
                    let active = decode_flow_active(&args);
                    self.with_driver_control(endpoint, |d, c| d.on_flow_ok(c, channel, active));
                }
                _ => {}
            }
            return;
        }

        if class_id == class::EXCHANGE {
            match method_id {
                exchange_ids::DECLARE_OK => {
                    self.with_driver_control(endpoint, |d, c| d.on_exchange_declare_ok(c, channel));
                }
                exchange_ids::DELETE_OK => {
                    self.with_driver_control(endpoint, |d, c| d.on_exchange_delete_ok(c, channel));
                }
                _ => {}
            }
            return;
        }

        if class_id == class::QUEUE {
            match method_id {
                queue_ids::DECLARE_OK => match QueueDeclareOk::decode(&args) {
                    Ok(ok) => {
                        self.with_driver_control(endpoint, |d, c| {
                            d.on_queue_declare_ok(
                                c,
                                channel,
                                &ok.queue,
                                ok.message_count,
                                ok.consumer_count,
                            );
                        });
                    }
                    Err(e) => self.fail_io(endpoint, &e.to_string()),
                },
                queue_ids::BIND_OK => {
                    self.with_driver_control(endpoint, |d, c| d.on_queue_bind_ok(c, channel));
                }
                queue_ids::UNBIND_OK => {
                    self.with_driver_control(endpoint, |d, c| d.on_queue_unbind_ok(c, channel));
                }
                queue_ids::PURGE_OK => {
                    let count = args
                        .get(..4)
                        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                        .unwrap_or(0);
                    self.with_driver_control(endpoint, |d, c| {
                        d.on_queue_purge_ok(c, channel, count);
                    });
                }
                queue_ids::DELETE_OK => {
                    let count = args
                        .get(..4)
                        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                        .unwrap_or(0);
                    self.with_driver_control(endpoint, |d, c| {
                        d.on_queue_delete_ok(c, channel, count);
                    });
                }
                _ => {}
            }
            return;
        }

        if class_id == class::CONFIRM {
            if method_id == confirm::SELECT_OK {
                self.with_driver_control(endpoint, |d, c| d.on_confirm_select_ok(c, channel));
            }
            return;
        }

        if class_id == class::TX {
            match method_id {
                tx::SELECT_OK => {
                    self.with_driver_control(endpoint, |d, c| d.on_tx_select_ok(c, channel));
                }
                tx::COMMIT_OK => {
                    self.with_driver_control(endpoint, |d, c| d.on_tx_commit_ok(c, channel));
                }
                tx::ROLLBACK_OK => {
                    self.with_driver_control(endpoint, |d, c| d.on_tx_rollback_ok(c, channel));
                }
                _ => {}
            }
            return;
        }

        if class_id == class::BASIC {
            match method_id {
                basic::QOS_OK => {
                    self.with_driver_control(endpoint, |d, c| d.on_basic_qos_ok(c, channel));
                }
                basic::CONSUME_OK => match decode_consumer_tag(&args) {
                    Ok(tag) => {
                        self.with_driver_control(endpoint, |d, c| d.on_consume_ok(c, channel, &tag));
                    }
                    Err(e) => self.fail_io(endpoint, &e.to_string()),
                },
                basic::CANCEL_OK => match decode_consumer_tag(&args) {
                    Ok(tag) => {
                        self.with_driver_control(endpoint, |d, c| d.on_cancel_ok(c, channel, &tag));
                    }
                    Err(e) => self.fail_io(endpoint, &e.to_string()),
                },
                basic::CANCEL => match decode_basic_cancel(&args) {
                    // Broker-initiated consumer-cancel-notify (RabbitMQ
                    // extension), not a reply to our own basic_cancel.
                    Ok((tag, no_wait)) => {
                        if !no_wait {
                            match encode_basic_cancel_ok(&tag) {
                                Ok(a) => self.send_method(
                                    endpoint,
                                    channel,
                                    class::BASIC,
                                    basic::CANCEL_OK,
                                    &a,
                                ),
                                Err(e) => {
                                    self.fail_io(endpoint, &e.to_string());
                                    return;
                                }
                            }
                        }
                        self.with_driver_control(endpoint, |d, c| {
                            d.on_consumer_cancelled(c, channel, &tag);
                        });
                    }
                    Err(e) => self.fail_io(endpoint, &e.to_string()),
                },
                basic::DELIVER => match BasicDeliver::decode(&args) {
                    Ok(d) => {
                        self.pending_content = Some(PendingContent::Deliver(d));
                        self.content_is_return = false;
                    }
                    Err(e) => self.fail_io(endpoint, &e.to_string()),
                },
                basic::RETURN => match BasicReturn::decode(&args) {
                    Ok(r) => {
                        self.pending_content = Some(PendingContent::Return(r));
                        self.content_is_return = true;
                    }
                    Err(e) => self.fail_io(endpoint, &e.to_string()),
                },
                basic::GET_OK => match BasicGetOk::decode(&args) {
                    Ok(ok) => {
                        self.pending_content = Some(PendingContent::Get(ok));
                        self.content_is_return = false;
                    }
                    Err(e) => self.fail_io(endpoint, &e.to_string()),
                },
                basic::GET_EMPTY => {
                    self.with_driver_control(endpoint, |d, c| d.on_get_empty(c, channel));
                }
                basic::RECOVER_OK => {
                    self.with_driver_control(endpoint, |d, c| d.on_recover_ok(c, channel));
                }
                basic::ACK => match decode_ack(&args) {
                    Ok((tag, multiple)) => {
                        self.with_driver_control(endpoint, |d, c| d.on_ack(c, channel, tag, multiple));
                    }
                    Err(e) => self.fail_io(endpoint, &e.to_string()),
                },
                basic::NACK => match decode_nack(&args) {
                    Ok((tag, multiple, requeue)) => {
                        self.with_driver_control(endpoint, |d, c| {
                            d.on_nack(c, channel, tag, multiple, requeue);
                        });
                    }
                    Err(e) => self.fail_io(endpoint, &e.to_string()),
                },
                _ => {}
            }
        }
    }

    fn handle_content_header(
        &mut self,
        endpoint: &mut dyn Endpoint,
        channel: u16,
        _class_id: u16,
        body_size: u64,
        properties: BasicProperties,
    ) {
        self.pending_props = Some(properties);
        self.pending_body_len = body_size;
        self.pending_body_received = 0;

        let props = self.pending_props.clone().unwrap_or_default();
        match self.pending_content.take() {
            Some(PendingContent::Deliver(d)) => {
                self.pending_content = Some(PendingContent::Deliver(d.clone()));
                if let Some(ref mut driver) = self.driver {
                    driver.on_delivery_start(
                        channel,
                        &d.consumer_tag,
                        d.delivery_tag,
                        d.redelivered,
                        &d.exchange,
                        &d.routing_key,
                        &props,
                        body_size,
                    );
                }
                if body_size == 0 {
                    self.finish_content(endpoint, channel);
                }
            }
            Some(PendingContent::Return(r)) => {
                self.pending_content = Some(PendingContent::Return(r.clone()));
                if let Some(ref mut driver) = self.driver {
                    driver.on_return_start(
                        channel,
                        r.reply_code,
                        &r.reply_text,
                        &r.exchange,
                        &r.routing_key,
                        &props,
                        body_size,
                    );
                }
                if body_size == 0 {
                    self.finish_content(endpoint, channel);
                }
            }
            Some(PendingContent::Get(ok)) => {
                self.pending_content = Some(PendingContent::Get(ok.clone()));
                self.with_driver_control(endpoint, |d, c| {
                    d.on_get_ok(
                        c,
                        channel,
                        ok.delivery_tag,
                        ok.redelivered,
                        &ok.exchange,
                        &ok.routing_key,
                        ok.message_count,
                        &props,
                        body_size,
                    );
                });
                if body_size == 0 {
                    self.finish_content(endpoint, channel);
                }
            }
            None => {
                self.fail_io(endpoint, "content header without deliver/return");
            }
        }
    }

    fn handle_content_body(&mut self, endpoint: &mut dyn Endpoint, channel: u16, data: &[u8]) {
        self.pending_body_received += data.len() as u64;
        if self.content_is_return {
            if let Some(ref mut driver) = self.driver {
                driver.on_return_data(data);
            }
        } else if let Some(ref mut driver) = self.driver {
            driver.on_delivery_data(data);
        }
        if self.pending_body_received >= self.pending_body_len {
            self.finish_content(endpoint, channel);
        }
    }

    fn finish_content(&mut self, endpoint: &mut dyn Endpoint, channel: u16) {
        let is_return = self.content_is_return;
        self.pending_content = None;
        self.pending_props = None;
        self.pending_body_len = 0;
        self.pending_body_received = 0;
        if is_return {
            self.with_driver_control(endpoint, |d, c| d.on_return_complete(c, channel));
        } else {
            self.with_driver_control(endpoint, |d, c| d.on_delivery_complete(c, channel));
        }
    }
}

fn negotiate_max_u16(broker: u16, client: u16, default: u16) -> u16 {
    let b = if broker == 0 { default } else { broker };
    let c = if client == 0 { b } else { client };
    b.min(c)
}

fn negotiate_max_u32(broker: u32, client: u32, default: u32) -> u32 {
    let b = if broker == 0 { default } else { broker };
    let c = if client == 0 { b } else { client };
    b.min(c)
}

fn negotiate_heartbeat(broker: u16, client: u16) -> u16 {
    // Spec: min of non-zero; 0 from both means disabled.
    match (broker, client) {
        (0, 0) => 0,
        (0, c) => c,
        (b, 0) => b,
        (b, c) => b.min(c),
    }
}

/// Pick the SASL mechanism wire name to send in `connection.start-ok`.
///
/// If `forced` is set, it must appear (case-insensitively) in `advertised`
/// or this fails clearly rather than silently substituting a different
/// mechanism. Otherwise, the original unconditional default: the first of
/// PLAIN, then AMQPLAIN, that the broker advertises.
fn choose_mechanism(forced: Option<&str>, advertised: &[&str]) -> Result<String, AmqpError> {
    if let Some(name) = forced {
        if advertised.iter().any(|m| m.eq_ignore_ascii_case(name)) {
            Ok(name.to_owned())
        } else {
            Err(AmqpError::Malformed(
                "broker does not advertise the requested SASL mechanism",
            ))
        }
    } else {
        ["PLAIN", "AMQPLAIN"]
            .into_iter()
            .find(|want| advertised.iter().any(|m| m.eq_ignore_ascii_case(want)))
            .map(str::to_owned)
            .ok_or(AmqpError::Malformed("no supported SASL mechanism"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefers_plain_over_amqplain() {
        assert_eq!(
            choose_mechanism(None, &["AMQPLAIN", "PLAIN"]).unwrap(),
            "PLAIN"
        );
    }

    #[test]
    fn default_falls_back_to_amqplain() {
        assert_eq!(
            choose_mechanism(None, &["AMQPLAIN", "EXTERNAL"]).unwrap(),
            "AMQPLAIN"
        );
    }

    #[test]
    fn default_errors_when_neither_advertised() {
        assert!(choose_mechanism(None, &["EXTERNAL", "GSSAPI"]).is_err());
    }

    #[test]
    fn forced_mechanism_used_case_insensitively_when_advertised() {
        assert_eq!(
            choose_mechanism(Some("external"), &["PLAIN", "EXTERNAL"]).unwrap(),
            "external"
        );
    }

    #[test]
    fn forced_mechanism_errors_when_not_advertised() {
        assert!(choose_mechanism(Some("EXTERNAL"), &["PLAIN", "AMQPLAIN"]).is_err());
    }
}

/// Temporary control adapter that holds `&mut AmqpClientEndpoint` + endpoint.
struct ControlAdapter<'a> {
    inner: &'a mut AmqpClientEndpoint,
    endpoint: &'a mut dyn Endpoint,
}

impl AmqpClientControl for ControlAdapter<'_> {
    fn channel_open(&mut self, channel_id: u16) {
        if channel_id == 0 || channel_id > self.inner.negotiated_channel_max {
            return;
        }
        match encode_channel_open() {
            Ok(args) => self.inner.send_method(
                self.endpoint,
                channel_id,
                class::CHANNEL,
                channel_ids::OPEN,
                &args,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn channel_close(&mut self, channel_id: u16, reply_code: u16, reply_text: &str) {
        let args = CloseArgs {
            reply_code,
            reply_text: reply_text.to_owned(),
            class_id: 0,
            method_id: 0,
        };
        match args.encode() {
            Ok(a) => self.inner.send_method(
                self.endpoint,
                channel_id,
                class::CHANNEL,
                channel_ids::CLOSE,
                &a,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn exchange_declare(
        &mut self,
        channel: u16,
        exchange: &str,
        exchange_type: &str,
        passive: bool,
        durable: bool,
        auto_delete: bool,
        internal: bool,
        arguments: &FieldTable,
    ) {
        match encode_exchange_declare(
            exchange,
            exchange_type,
            passive,
            durable,
            auto_delete,
            internal,
            false,
            arguments,
        ) {
            Ok(args) => self.inner.send_method(
                self.endpoint,
                channel,
                class::EXCHANGE,
                exchange_ids::DECLARE,
                &args,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn exchange_delete(&mut self, channel: u16, exchange: &str, if_unused: bool) {
        match encode_exchange_delete(exchange, if_unused, false) {
            Ok(args) => self.inner.send_method(
                self.endpoint,
                channel,
                class::EXCHANGE,
                exchange_ids::DELETE,
                &args,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn queue_declare(
        &mut self,
        channel: u16,
        queue: &str,
        passive: bool,
        durable: bool,
        exclusive: bool,
        auto_delete: bool,
        arguments: &FieldTable,
    ) {
        match encode_queue_declare(queue, passive, durable, exclusive, auto_delete, false, arguments)
        {
            Ok(args) => self.inner.send_method(
                self.endpoint,
                channel,
                class::QUEUE,
                queue_ids::DECLARE,
                &args,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn queue_bind(
        &mut self,
        channel: u16,
        queue: &str,
        exchange: &str,
        routing_key: &str,
        arguments: &FieldTable,
    ) {
        match encode_queue_bind(queue, exchange, routing_key, false, arguments) {
            Ok(args) => self.inner.send_method(
                self.endpoint,
                channel,
                class::QUEUE,
                queue_ids::BIND,
                &args,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn queue_unbind(
        &mut self,
        channel: u16,
        queue: &str,
        exchange: &str,
        routing_key: &str,
        arguments: &FieldTable,
    ) {
        match encode_queue_unbind(queue, exchange, routing_key, arguments) {
            Ok(args) => self.inner.send_method(
                self.endpoint,
                channel,
                class::QUEUE,
                queue_ids::UNBIND,
                &args,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn queue_purge(&mut self, channel: u16, queue: &str) {
        match encode_queue_purge(queue, false) {
            Ok(args) => self.inner.send_method(
                self.endpoint,
                channel,
                class::QUEUE,
                queue_ids::PURGE,
                &args,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn queue_delete(&mut self, channel: u16, queue: &str, if_unused: bool, if_empty: bool) {
        match encode_queue_delete(queue, if_unused, if_empty, false) {
            Ok(args) => self.inner.send_method(
                self.endpoint,
                channel,
                class::QUEUE,
                queue_ids::DELETE,
                &args,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn confirm_select(&mut self, channel: u16) {
        let args = encode_confirm_select(false);
        self.inner.send_method(
            self.endpoint,
            channel,
            class::CONFIRM,
            confirm::SELECT,
            &args,
        );
        self.inner.next_publish_tag.entry(channel).or_insert(1);
    }

    fn basic_publish(
        &mut self,
        channel: u16,
        exchange: &str,
        routing_key: &str,
        mandatory: bool,
        immediate: bool,
        properties: &BasicProperties,
        body: &[u8],
    ) {
        match encode_basic_publish(exchange, routing_key, mandatory, immediate) {
            Ok(args) => {
                self.inner.send_method(
                    self.endpoint,
                    channel,
                    class::BASIC,
                    basic::PUBLISH,
                    &args,
                );
                match encode_content(channel, properties, body, self.inner.negotiated_frame_max) {
                    Ok(frames) => {
                        self.endpoint.send(&frames);
                        if let Some(tag) = self.inner.next_publish_tag.get_mut(&channel) {
                            *tag = tag.saturating_add(1);
                        }
                    }
                    Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
                }
            }
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn basic_qos(&mut self, channel: u16, prefetch_size: u32, prefetch_count: u16, global: bool) {
        let args = encode_basic_qos(prefetch_size, prefetch_count, global);
        self.inner
            .send_method(self.endpoint, channel, class::BASIC, basic::QOS, &args);
    }

    fn basic_consume(
        &mut self,
        channel: u16,
        queue: &str,
        consumer_tag: &str,
        no_local: bool,
        no_ack: bool,
        exclusive: bool,
        arguments: &FieldTable,
    ) {
        match encode_basic_consume(
            queue,
            consumer_tag,
            no_local,
            no_ack,
            exclusive,
            false,
            arguments,
        ) {
            Ok(args) => self.inner.send_method(
                self.endpoint,
                channel,
                class::BASIC,
                basic::CONSUME,
                &args,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn basic_cancel(&mut self, channel: u16, consumer_tag: &str) {
        match encode_basic_cancel(consumer_tag, false) {
            Ok(args) => self.inner.send_method(
                self.endpoint,
                channel,
                class::BASIC,
                basic::CANCEL,
                &args,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn basic_ack(&mut self, channel: u16, delivery_tag: u64, multiple: bool) {
        let args = encode_basic_ack(delivery_tag, multiple);
        self.inner
            .send_method(self.endpoint, channel, class::BASIC, basic::ACK, &args);
    }

    fn basic_nack(&mut self, channel: u16, delivery_tag: u64, multiple: bool, requeue: bool) {
        let args = encode_basic_nack(delivery_tag, multiple, requeue);
        self.inner
            .send_method(self.endpoint, channel, class::BASIC, basic::NACK, &args);
    }

    fn basic_reject(&mut self, channel: u16, delivery_tag: u64, requeue: bool) {
        let args = encode_basic_reject(delivery_tag, requeue);
        self.inner
            .send_method(self.endpoint, channel, class::BASIC, basic::REJECT, &args);
    }

    fn basic_get(&mut self, channel: u16, queue: &str, no_ack: bool) {
        match encode_basic_get(queue, no_ack) {
            Ok(args) => {
                self.inner
                    .send_method(self.endpoint, channel, class::BASIC, basic::GET, &args);
            }
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }

    fn basic_recover(&mut self, channel: u16, requeue: bool) {
        let args = encode_basic_recover(requeue);
        self.inner
            .send_method(self.endpoint, channel, class::BASIC, basic::RECOVER, &args);
    }

    fn flow(&mut self, channel: u16, active: bool) {
        let args = encode_channel_flow(active);
        self.inner.send_method(
            self.endpoint,
            channel,
            class::CHANNEL,
            channel_ids::FLOW,
            &args,
        );
    }

    fn tx_select(&mut self, channel: u16) {
        self.inner
            .send_method(self.endpoint, channel, class::TX, tx::SELECT, &encode_tx_method());
    }

    fn tx_commit(&mut self, channel: u16) {
        self.inner
            .send_method(self.endpoint, channel, class::TX, tx::COMMIT, &encode_tx_method());
    }

    fn tx_rollback(&mut self, channel: u16) {
        self.inner.send_method(
            self.endpoint,
            channel,
            class::TX,
            tx::ROLLBACK,
            &encode_tx_method(),
        );
    }

    fn connection_close(&mut self, reply_code: u16, reply_text: &str) {
        let args = CloseArgs {
            reply_code,
            reply_text: reply_text.to_owned(),
            class_id: 0,
            method_id: 0,
        };
        match args.encode() {
            Ok(a) => self.inner.send_method(
                self.endpoint,
                0,
                class::CONNECTION,
                connection::CLOSE,
                &a,
            ),
            Err(e) => self.inner.fail_io(self.endpoint, &e.to_string()),
        }
    }
}

/// Bridge parser callbacks into the endpoint while `receive` holds `&mut Endpoint`.
struct ReceiveHandler<'a> {
    ep: &'a mut AmqpClientEndpoint,
    endpoint: &'a mut dyn Endpoint,
}

impl AmqpFrameHandler for ReceiveHandler<'_> {
    fn method(&mut self, frame: MethodFrame) {
        self.ep.handle_method(self.endpoint, frame);
    }

    fn content_header(
        &mut self,
        channel: u16,
        class_id: u16,
        body_size: u64,
        properties: BasicProperties,
    ) {
        self.ep
            .handle_content_header(self.endpoint, channel, class_id, body_size, properties);
    }

    fn content_body(&mut self, channel: u16, data: &[u8]) {
        self.ep.handle_content_body(self.endpoint, channel, data);
    }

    fn heartbeat(&mut self) {
        self.ep.rearm_heartbeat_recv(self.endpoint);
    }

    fn error(&mut self, err: AmqpError) {
        self.ep.fail_io(self.endpoint, &err.to_string());
    }
}

impl ProtocolHandler for AmqpClientEndpoint {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        endpoint.send(encode_protocol_header());
        self.arm_handshake_timer(endpoint);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        // Take ownership of parser temporarily to avoid borrow conflicts.
        let mut parser = std::mem::replace(
            &mut self.parser,
            AmqpFrameParser::new(self.negotiated_frame_max),
        );
        {
            let mut handler = ReceiveHandler {
                ep: self,
                endpoint,
            };
            parser.feed(data, &mut handler);
        }
        self.parser = parser;
        // Compact: consume all fed bytes (parser owns its buffer).
        *data = &[];
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        if let Some(ref mut d) = self.driver {
            d.on_disconnected();
        }
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error) {
        if err.kind() == io::ErrorKind::TimedOut && err.to_string().contains(HEARTBEAT_DUE) {
            endpoint.send(&encode_heartbeat());
            self.rearm_heartbeat_send(endpoint);
            return;
        }
        if let Some(ref mut d) = self.driver {
            d.on_error(err);
        }
    }
}
