// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in RabbitMQ integration test.
//!
//! Run with a broker available:
//! `cargo test -p hopf-amqp --features integration -- --nocapture`
//!
//! Env overrides: `HOPF_AMQP_HOST`, `HOPF_AMQP_PORT`, `HOPF_AMQP_USER`, `HOPF_AMQP_PASS`.

use std::io;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hopf_core::{Runtime, RuntimeConfig};

use crate::client::{
    AmqpClient, AmqpClientControl, AmqpClientDriver, AmqpClientHandlerFactory,
    AmqpRecoveringClient, RecoveryListener,
};
use crate::codec::{BasicProperties, FieldTable, FieldValue};

#[derive(Default, Clone)]
struct State {
    opened: bool,
    declared: bool,
    consumed: bool,
    published: bool,
    delivered: bool,
    acked_pub: bool,
    error: Option<String>,
}

struct IntegDriver {
    queue: String,
    state: Arc<Mutex<State>>,
    pending_tag: Option<(u16, u64)>,
}

impl AmqpClientDriver for IntegDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        self.state.lock().unwrap().opened = true;
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.confirm_select(channel);
        client.queue_declare(
            channel,
            &self.queue,
            false,
            false,
            true,
            true,
            &FieldTable::new(),
        );
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}

    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_confirm_select_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        queue: &str,
        _: u32,
        _: u32,
    ) {
        self.state.lock().unwrap().declared = true;
        client.basic_consume(channel, queue, "", false, false, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, _: &str) {
        self.state.lock().unwrap().consumed = true;
        let mut props = BasicProperties::new();
        props.content_type = Some("text/plain".into());
        client.basic_publish(
            channel,
            "",
            &self.queue,
            false,
            false,
            &props,
            b"hopf-amqp integration",
        );
        self.state.lock().unwrap().published = true;
    }

    fn on_delivery_start(
        &mut self,
        channel: u16,
        _: &str,
        delivery_tag: u64,
        _: bool,
        _: &str,
        _: &str,
        _: &BasicProperties,
        _: u64,
    ) {
        self.pending_tag = Some((channel, delivery_tag));
    }

    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        self.state.lock().unwrap().delivered = true;
        if let Some((ch, tag)) = self.pending_tag.take() {
            if ch == channel {
                client.basic_ack(channel, tag, false);
            }
        }
    }

    fn on_ack(&mut self, client: &mut dyn AmqpClientControl, _: u16, _: u64, _: bool) {
        self.state.lock().unwrap().acked_pub = true;
        client.connection_close(200, "integration done");
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct IntegFactory {
    queue: String,
    state: Arc<Mutex<State>>,
}

impl AmqpClientHandlerFactory for IntegFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(IntegDriver {
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
            pending_tag: None,
        })
    }
}

/// `(host, port, user, pass)` from the same env overrides every integration
/// test in this module uses.
fn broker_creds() -> (String, u16, String, String) {
    let host = std::env::var("HOPF_AMQP_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("HOPF_AMQP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5672);
    let user = std::env::var("HOPF_AMQP_USER").unwrap_or_else(|_| "guest".into());
    let pass = std::env::var("HOPF_AMQP_PASS").unwrap_or_else(|_| "guest".into());
    (host, port, user, pass)
}

/// `(tls_port, ca_cert_path)` for the amqps (implicit TLS) listener. The CA
/// path defaults to the self-signed cert this crate's local dev broker is
/// configured with (see the repo's integration-test setup instructions) —
/// override both via env for a differently configured broker.
fn broker_tls_params() -> (u16, std::path::PathBuf) {
    let port: u16 = std::env::var("HOPF_AMQP_TLS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5671);
    let ca_path = std::env::var("HOPF_AMQP_TLS_CA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").expect("HOME not set");
            std::path::PathBuf::from(home).join(".hopf-rabbitmq-tls/ca-cert.pem")
        });
    (port, ca_path)
}

/// Poll `state` (as returned by `snapshot`) until `done` reports true, an
/// error is recorded, or `deadline_secs` elapses — printing `label` on
/// timeout so failures identify which round-trip stalled.
fn wait_for<S: Clone>(
    state: &Arc<Mutex<S>>,
    deadline_secs: u64,
    error: impl Fn(&S) -> &Option<String>,
    done: impl Fn(&S) -> bool,
    label: &str,
) -> S {
    let deadline = Instant::now() + Duration::from_secs(deadline_secs);
    loop {
        {
            let s = state.lock().unwrap();
            if let Some(e) = error(&s) {
                panic!("amqp error: {e}");
            }
            if done(&s) {
                return s.clone();
            }
        }
        if Instant::now() > deadline {
            panic!("timeout waiting for {label}");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn publish_consume_roundtrip() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.{}", std::process::id());

    let state = Arc::new(Mutex::new(State::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(
            &rt,
            Arc::new(IntegFactory {
                queue,
                state: Arc::clone(&state),
            }),
        )
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.delivered && s.acked_pub,
        "publish/consume round-trip",
    );
    assert!(s.opened && s.declared && s.consumed && s.published);
}

/// Same publish/consume round-trip as `publish_consume_roundtrip`, but over
/// implicit TLS (amqps, port 5671) against the broker's leaf certificate,
/// issued by a throwaway local CA generated for this dev broker. The client
/// trusts that CA (`hopf_tls::connector_from_pem`), the standard way a
/// private/self-signed CA is pinned — not a bypass of certificate
/// verification.
///
/// Requires the local broker's TLS listener to be configured with the
/// matching leaf cert; the CA it should be trusted against is read from
/// `HOPF_AMQP_TLS_CA` (defaulting to `~/.hopf-rabbitmq-tls/ca-cert.pem`) —
/// skipped if that file isn't present, since amqps isn't part of every dev
/// environment's broker setup.
#[test]
fn amqps_publish_consume_roundtrip_over_implicit_tls() {
    let (host, _plain_port, user, pass) = broker_creds();
    let (tls_port, ca_path) = broker_tls_params();
    if !ca_path.exists() {
        eprintln!(
            "skipping amqps_publish_consume_roundtrip_over_implicit_tls: no CA cert at {}",
            ca_path.display()
        );
        return;
    }
    let connector = hopf_tls::connector_from_pem(&ca_path, &[]).expect("tls connector");

    let queue = format!("hopf.amqp.integ.tls.{}", std::process::id());
    let state = Arc::new(Mutex::new(State::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, tls_port)
        .credentials(user, pass)
        .implicit_tls(connector, "localhost")
        .connect(
            &rt,
            Arc::new(IntegFactory {
                queue,
                state: Arc::clone(&state),
            }),
        )
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.delivered && s.acked_pub,
        "amqps publish/consume round-trip",
    );
    assert!(s.opened && s.declared && s.consumed && s.published);
}

/// Same round-trip, but with the SASL mechanism forced via
/// [`AmqpClient::mechanism`] instead of auto-negotiated — exercises the
/// hopf_auth-backed PLAIN path explicitly rather than incidentally.
#[test]
fn publish_consume_roundtrip_with_forced_plain_mechanism() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.plain.{}", std::process::id());

    let state = Arc::new(Mutex::new(State::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .mechanism("PLAIN")
        .connect(
            &rt,
            Arc::new(IntegFactory {
                queue,
                state: Arc::clone(&state),
            }),
        )
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.delivered && s.acked_pub,
        "forced-PLAIN publish/consume round-trip",
    );
    assert!(s.opened && s.declared && s.consumed && s.published);
}

#[derive(Default, Clone)]
struct TxState {
    committed: bool,
    delivered_after_commit: bool,
    error: Option<String>,
}

struct TxDriver {
    queue: String,
    state: Arc<Mutex<TxState>>,
    published: bool,
}

impl AmqpClientDriver for TxDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.tx_select(channel);
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}

    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_tx_select_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(
            channel,
            &self.queue,
            false,
            false,
            true,
            true,
            &FieldTable::new(),
        );
    }

    fn on_queue_declare_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        queue: &str,
        _: u32,
        _: u32,
    ) {
        client.basic_consume(channel, queue, "", false, true, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, _: &str) {
        // Published inside the still-open transaction: must not be
        // delivered to the consumer until tx_commit.
        client.basic_publish(
            channel,
            "",
            &self.queue,
            false,
            false,
            &BasicProperties::new(),
            b"tx-message",
        );
        self.published = true;
        client.tx_commit(channel);
    }

    fn on_tx_commit_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {
        self.state.lock().unwrap().committed = true;
    }

    fn on_delivery_start(
        &mut self,
        _: u16,
        _: &str,
        _: u64,
        _: bool,
        _: &str,
        _: &str,
        _: &BasicProperties,
        _: u64,
    ) {
    }

    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        let mut s = self.state.lock().unwrap();
        // If this fires before `committed`, tx isolation is broken.
        s.delivered_after_commit = s.committed;
        drop(s);
        client.connection_close(200, "tx integration done");
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct TxFactory {
    queue: String,
    state: Arc<Mutex<TxState>>,
}

impl AmqpClientHandlerFactory for TxFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(TxDriver {
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
            published: false,
        })
    }
}

/// A message published inside a transaction must only reach a consumer
/// once the transaction commits (RFC: AMQP 0-9-1 §1.9, `tx` class).
#[test]
fn tx_commit_gates_delivery() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.tx.{}", std::process::id());

    let state = Arc::new(Mutex::new(TxState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(
            &rt,
            Arc::new(TxFactory {
                queue,
                state: Arc::clone(&state),
            }),
        )
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.delivered_after_commit,
        "tx commit + delivery",
    );
    assert!(s.committed);
    assert!(s.delivered_after_commit, "message delivered before commit");
}

#[derive(Default, Clone)]
struct GetState {
    got_message: bool,
    got_empty: bool,
    error: Option<String>,
}

struct GetDriver {
    queue: String,
    state: Arc<Mutex<GetState>>,
}

impl AmqpClientDriver for GetDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(
            channel,
            &self.queue,
            false,
            false,
            true,
            true,
            &FieldTable::new(),
        );
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}

    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}

    fn on_queue_declare_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        queue: &str,
        _: u32,
        _: u32,
    ) {
        client.basic_publish(
            channel,
            "",
            queue,
            false,
            false,
            &BasicProperties::new(),
            b"get-message",
        );
        // No publisher confirms on this channel — fixed delay stands in for
        // "publish has reached the broker" before polling for it.
        thread::sleep(Duration::from_millis(200));
        client.basic_get(channel, &self.queue, false);
    }

    fn on_delivery_start(
        &mut self,
        _: u16,
        _: &str,
        _: u64,
        _: bool,
        _: &str,
        _: &str,
        _: &BasicProperties,
        _: u64,
    ) {
    }

    #[allow(clippy::too_many_arguments)]
    fn on_get_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        delivery_tag: u64,
        _: bool,
        _: &str,
        _: &str,
        _: u32,
        _: &BasicProperties,
        _: u64,
    ) {
        self.state.lock().unwrap().got_message = true;
        client.basic_ack(channel, delivery_tag, false);
        // Second get on the now-empty queue must report get-empty.
        client.basic_get(channel, &self.queue, false);
    }

    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_get_empty(&mut self, client: &mut dyn AmqpClientControl, _: u16) {
        self.state.lock().unwrap().got_empty = true;
        client.connection_close(200, "get integration done");
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct GetFactory {
    queue: String,
    state: Arc<Mutex<GetState>>,
}

impl AmqpClientHandlerFactory for GetFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(GetDriver {
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
        })
    }
}

#[test]
fn basic_get_then_empty() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.get.{}", std::process::id());

    let state = Arc::new(Mutex::new(GetState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(
            &rt,
            Arc::new(GetFactory {
                queue,
                state: Arc::clone(&state),
            }),
        )
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.got_empty,
        "basic.get then basic.get-empty",
    );
    assert!(s.got_message);
    assert!(s.got_empty);
}

#[derive(Default, Clone)]
struct RecoverState {
    first_delivery_redelivered: Option<bool>,
    second_delivery_redelivered: Option<bool>,
    recovered: bool,
    error: Option<String>,
}

struct RecoverDriver {
    queue: String,
    state: Arc<Mutex<RecoverState>>,
    deliveries: u32,
}

impl AmqpClientDriver for RecoverDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(
            channel,
            &self.queue,
            false,
            false,
            true,
            true,
            &FieldTable::new(),
        );
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}

    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}

    fn on_queue_declare_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        queue: &str,
        _: u32,
        _: u32,
    ) {
        client.basic_publish(
            channel,
            "",
            queue,
            false,
            false,
            &BasicProperties::new(),
            b"recover-message",
        );
        client.basic_consume(channel, queue, "", false, false, false, &FieldTable::new());
    }

    fn on_delivery_start(
        &mut self,
        _: u16,
        _: &str,
        _: u64,
        redelivered: bool,
        _: &str,
        _: &str,
        _: &BasicProperties,
        _: u64,
    ) {
        self.deliveries += 1;
        let mut s = self.state.lock().unwrap();
        if self.deliveries == 1 {
            s.first_delivery_redelivered = Some(redelivered);
        } else {
            s.second_delivery_redelivered = Some(redelivered);
        }
    }

    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        // Deliberately never ack: the first delivery is left outstanding so
        // basic.recover(requeue=true) has something to redeliver.
        if self.deliveries == 1 {
            client.basic_recover(channel, true);
        } else {
            client.connection_close(200, "recover integration done");
        }
    }

    fn on_recover_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {
        self.state.lock().unwrap().recovered = true;
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct RecoverFactory {
    queue: String,
    state: Arc<Mutex<RecoverState>>,
}

impl AmqpClientHandlerFactory for RecoverFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(RecoverDriver {
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
            deliveries: 0,
        })
    }
}

#[test]
fn basic_recover_redelivers_unacked_message() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.recover.{}", std::process::id());

    let state = Arc::new(Mutex::new(RecoverState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(
            &rt,
            Arc::new(RecoverFactory {
                queue,
                state: Arc::clone(&state),
            }),
        )
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.second_delivery_redelivered.is_some(),
        "basic.recover redelivery",
    );
    assert!(s.recovered);
    assert_eq!(s.first_delivery_redelivered, Some(false));
    assert_eq!(s.second_delivery_redelivered, Some(true));
}

#[derive(Default, Clone)]
struct FlowState {
    close_code: Option<u16>,
    close_text: Option<String>,
    error: Option<String>,
}

struct FlowDriver {
    state: Arc<Mutex<FlowState>>,
}

impl AmqpClientDriver for FlowDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.flow(channel, false);
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}

    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str, _: u32, _: u32) {}

    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}

    fn on_delivery_start(
        &mut self,
        _: u16,
        _: &str,
        _: u64,
        _: bool,
        _: &str,
        _: &str,
        _: &BasicProperties,
        _: u64,
    ) {
    }

    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_flow_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: bool) {}

    fn on_connection_close(&mut self, reply_code: u16, reply_text: &str) {
        let mut s = self.state.lock().unwrap();
        s.close_code = Some(reply_code);
        s.close_text = Some(reply_text.to_string());
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct FlowFactory {
    state: Arc<Mutex<FlowState>>,
}

impl AmqpClientHandlerFactory for FlowFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(FlowDriver { state: Arc::clone(&self.state) })
    }
}

/// Issue #207: real RabbitMQ doesn't implement client-initiated pause
/// (`channel.flow` with `active=false`) — it rejects the request with a
/// hard connection-level exception (reply-code 540, `NOT_IMPLEMENTED`)
/// instead of replying `flow-ok`. This proves the client decodes and
/// surfaces that promptly via `on_connection_close`, rather than a caller
/// hanging indefinitely waiting for a `flow-ok` that will never arrive.
#[test]
fn client_initiated_flow_is_rejected_by_the_broker_with_a_prompt_connection_close() {
    let (host, port, user, pass) = broker_creds();

    let state = Arc::new(Mutex::new(FlowState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(FlowFactory { state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        5,
        |s| &s.error,
        |s| s.close_code.is_some(),
        "connection.close after client-initiated channel.flow",
    );
    assert_eq!(s.close_code, Some(540));
    assert!(
        s.close_text.as_deref().unwrap_or("").contains("NOT_IMPLEMENTED"),
        "unexpected close text: {:?}",
        s.close_text
    );
}

#[derive(Default, Clone)]
struct RecoveryState {
    first_consume_ok: bool,
    recovered: bool,
    redelivered_after_recovery: bool,
    error: Option<String>,
}

struct RecoveryDriver {
    queue: String,
    state: Arc<Mutex<RecoveryState>>,
    consume_ok_count: u32,
}

impl AmqpClientDriver for RecoveryDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(channel, &self.queue, false, false, true, true, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        queue: &str,
        _: u32,
        _: u32,
    ) {
        client.basic_consume(channel, queue, "", false, true, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, _: &str) {
        self.consume_ok_count += 1;
        if self.consume_ok_count == 1 {
            // First consume succeeded — mark it, then simulate an
            // unexpected drop. AmqpRecoveringClient can't tell this apart
            // from a real broker restart / network blip: on_disconnected
            // fires either way and (since we never called
            // AmqpRecoveringHandle::close()) triggers reconnect + replay.
            self.state.lock().unwrap().first_consume_ok = true;
            client.connection_close(200, "integration test induced disconnect");
        } else {
            // Reconnect replayed queue_declare + basic_consume, producing
            // this second consume-ok — the queue/consumer are live again
            // with no code on our side re-running that choreography.
            let mut props = BasicProperties::new();
            props.content_type = Some("text/plain".into());
            client.basic_publish(channel, "", &self.queue, false, false, &props, b"post-recovery");
        }
    }

    fn on_delivery_start(
        &mut self,
        _: u16,
        _: &str,
        _: u64,
        _: bool,
        _: &str,
        _: &str,
        _: &BasicProperties,
        _: u64,
    ) {
    }
    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        self.state.lock().unwrap().redelivered_after_recovery = true;
        client.connection_close(200, "recovery integration done");
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct RecoveryFactory {
    queue: String,
    state: Arc<Mutex<RecoveryState>>,
}

impl AmqpClientHandlerFactory for RecoveryFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(RecoveryDriver {
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
            consume_ok_count: 0,
        })
    }
}

struct RecoveryListenerCapture {
    state: Arc<Mutex<RecoveryState>>,
}

impl RecoveryListener for RecoveryListenerCapture {
    fn on_recovered(&self) {
        self.state.lock().unwrap().recovered = true;
    }
}

/// Simulates an unexpected drop (a driver-initiated `connection_close` —
/// indistinguishable to the recovery layer from a real broker restart)
/// and verifies `AmqpRecoveringClient` reconnects, replays the
/// queue/consumer with no application code re-running that setup, and
/// `RecoveryListener::on_recovered` fires before the redelivered message
/// arrives.
#[test]
fn recovering_client_replays_topology_after_induced_disconnect() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.recovery.{}", std::process::id());

    let state = Arc::new(Mutex::new(RecoveryState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    // Bound to a variable and kept alive for the whole test (issue #208):
    // AmqpRecoveringHandle now stops the reconnect loop on Drop, so an
    // unbound temporary here would stop reconnection almost immediately —
    // before the induced disconnect below even has a chance to trigger it.
    let handle =
        AmqpRecoveringClient::new(AmqpClient::new(host, port).credentials(user, pass), Arc::clone(&rt))
            .recovery_listener(Arc::new(RecoveryListenerCapture { state: Arc::clone(&state) }))
            .connect(Arc::new(RecoveryFactory { queue, state: Arc::clone(&state) }))
            .expect("connect");

    let s = wait_for(
        &state,
        20,
        |s| &s.error,
        |s| s.redelivered_after_recovery,
        "reconnect + topology replay + post-recovery delivery",
    );
    assert!(s.first_consume_ok);
    assert!(s.recovered, "RecoveryListener::on_recovered must fire");
    assert!(s.redelivered_after_recovery);
    handle.close();
}

#[derive(Default, Clone)]
struct StreamingPublishState {
    body_matches: Option<bool>,
    error: Option<String>,
}

/// Deterministic, non-repeating byte pattern — repeating a single byte
/// wouldn't catch a chunk-boundary bug that just duplicates or drops a
/// chunk's worth of *identical* bytes.
fn test_body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

struct StreamingPublishDriver {
    queue: String,
    state: Arc<Mutex<StreamingPublishState>>,
    expected_body: Vec<u8>,
    received: Vec<u8>,
}

impl AmqpClientDriver for StreamingPublishDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(channel, &self.queue, false, false, true, true, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        queue: &str,
        _: u32,
        _: u32,
    ) {
        client.basic_consume(channel, queue, "", false, true, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, _: &str) {
        let mut props = BasicProperties::new();
        props.content_type = Some("application/octet-stream".into());
        client.basic_publish_start(
            channel, "", &self.queue, false, false, &props, self.expected_body.len() as u64,
        );
        // Chunk size deliberately doesn't divide the body length evenly,
        // and is unrelated to the broker's negotiated frame_max — the
        // point of streaming is that neither has to line up with the
        // other; basic_publish_body re-splits internally as needed.
        for chunk in self.expected_body.clone().chunks(4096) {
            client.basic_publish_body(channel, chunk);
        }
    }

    fn on_delivery_start(
        &mut self,
        _: u16,
        _: &str,
        _: u64,
        _: bool,
        _: &str,
        _: &str,
        _: &BasicProperties,
        body_len: u64,
    ) {
        self.received = Vec::with_capacity(body_len as usize);
    }

    fn on_delivery_data(&mut self, _channel: u16, data: &[u8]) {
        self.received.extend_from_slice(data);
    }

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        self.state.lock().unwrap().body_matches = Some(self.received == self.expected_body);
        client.connection_close(200, "streaming publish integration done");
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct StreamingPublishFactory {
    queue: String,
    state: Arc<Mutex<StreamingPublishState>>,
}

impl AmqpClientHandlerFactory for StreamingPublishFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(StreamingPublishDriver {
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
            // Deliberately larger than any reasonable frame_max, so
            // basic_publish_body's internal splitting is actually
            // exercised over multiple wire frames per chunk too.
            expected_body: test_body(200_000),
            received: Vec::new(),
        })
    }
}

/// Publishes a 200KB body via `basic_publish_start`/`basic_publish_body`
/// in 4096-byte pieces (neither aligned with the broker's frame_max nor
/// evenly dividing the body length) and verifies the consumer reassembles
/// exactly the original bytes.
#[test]
fn streaming_publish_reassembles_to_original_bytes() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.stream.{}", std::process::id());

    let state = Arc::new(Mutex::new(StreamingPublishState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(StreamingPublishFactory { queue, state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        20,
        |s| &s.error,
        |s| s.body_matches.is_some(),
        "streaming publish round-trip",
    );
    assert_eq!(s.body_matches, Some(true));
}

// ── Exchanges & routing ─────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct ExchangeRoutingState {
    // Keyed by queue name (also used as the consumer tag, so `on_delivery_start`
    // tells us directly which queue a delivery belongs to without extra bookkeeping).
    received: std::collections::HashMap<String, Vec<Vec<u8>>>,
    error: Option<String>,
}

/// Declares `exchange` (of `exchange_type`), declares one queue per
/// `(name, binding_key)` pair in `bindings`, binds each, and consumes on
/// all of them (consumer_tag = queue name). Once every queue has an active
/// consumer, `publish` is called once with `(channel, control)` so the
/// test can send whatever routing-key/body pairs it needs. Deliveries land
/// in `state.received[queue_name]`.
struct ExchangeRoutingDriver {
    exchange: String,
    exchange_type: &'static str,
    bindings: Vec<(String, String)>,
    state: Arc<Mutex<ExchangeRoutingState>>,
    declared: usize,
    consuming: usize,
    current_tag: Option<String>,
    current_buf: Vec<u8>,
    publish: Arc<dyn Fn(u16, &mut dyn AmqpClientControl) + Send + Sync>,
    published: bool,
}

impl AmqpClientDriver for ExchangeRoutingDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.exchange_declare(
            channel,
            &self.exchange,
            self.exchange_type,
            false,
            false,
            true,
            false,
            &FieldTable::new(),
        );
        let _ = channel;
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}

    fn on_exchange_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        for (queue, _) in &self.bindings {
            client.queue_declare(channel, queue, false, false, true, true, &FieldTable::new());
        }
    }

    fn on_queue_declare_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        queue: &str,
        _: u32,
        _: u32,
    ) {
        self.declared += 1;
        let routing_key = self
            .bindings
            .iter()
            .find(|(q, _)| q == queue)
            .map(|(_, k)| k.clone())
            .unwrap_or_default();
        client.queue_bind(channel, queue, &self.exchange, &routing_key, &FieldTable::new());
        client.basic_consume(channel, queue, queue, false, true, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, _consumer_tag: &str) {
        self.consuming += 1;
        if self.consuming == self.bindings.len() && !self.published {
            self.published = true;
            (self.publish.clone())(channel, client);
        }
    }

    fn on_delivery_start(
        &mut self,
        _channel: u16,
        consumer_tag: &str,
        _delivery_tag: u64,
        _redelivered: bool,
        _exchange: &str,
        _routing_key: &str,
        _properties: &BasicProperties,
        _body_len: u64,
    ) {
        self.current_tag = Some(consumer_tag.to_string());
        self.current_buf.clear();
    }

    fn on_delivery_data(&mut self, _channel: u16, data: &[u8]) {
        self.current_buf.extend_from_slice(data);
    }

    fn on_delivery_complete(&mut self, _client: &mut dyn AmqpClientControl, _channel: u16) {
        if let Some(tag) = self.current_tag.take() {
            let body = std::mem::take(&mut self.current_buf);
            self.state.lock().unwrap().received.entry(tag).or_default().push(body);
        }
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct ExchangeRoutingFactory {
    exchange: String,
    exchange_type: &'static str,
    bindings: Vec<(String, String)>,
    state: Arc<Mutex<ExchangeRoutingState>>,
    publish: Arc<dyn Fn(u16, &mut dyn AmqpClientControl) + Send + Sync>,
}

impl AmqpClientHandlerFactory for ExchangeRoutingFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(ExchangeRoutingDriver {
            exchange: self.exchange.clone(),
            exchange_type: self.exchange_type,
            bindings: self.bindings.clone(),
            state: Arc::clone(&self.state),
            declared: 0,
            consuming: 0,
            current_tag: None,
            current_buf: Vec::new(),
            publish: Arc::clone(&self.publish),
            published: false,
        })
    }
}

/// A direct exchange only routes a message to bindings whose key matches
/// the publish's routing key exactly (AMQP 0-9-1 §3.1.3.1) — not to every
/// bound queue.
#[test]
fn direct_exchange_routes_only_matching_binding_key() {
    let (host, port, user, pass) = broker_creds();
    let pid = std::process::id();
    let exchange = format!("hopf.amqp.integ.direct.{pid}");
    let q1 = format!("hopf.amqp.integ.direct.q1.{pid}");
    let q2 = format!("hopf.amqp.integ.direct.q2.{pid}");

    let state = Arc::new(Mutex::new(ExchangeRoutingState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    let ex_for_publish = exchange.clone();
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(
            &rt,
            Arc::new(ExchangeRoutingFactory {
                exchange: exchange.clone(),
                exchange_type: "direct",
                bindings: vec![(q1.clone(), "key1".into()), (q2.clone(), "key2".into())],
                state: Arc::clone(&state),
                publish: Arc::new(move |channel, client| {
                    client.basic_publish(channel, &ex_for_publish, "key1", false, false, &BasicProperties::new(), b"for-q1");
                    client.basic_publish(channel, &ex_for_publish, "key2", false, false, &BasicProperties::new(), b"for-q2");
                }),
            }),
        )
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.received.get(&q1).map(|v| v.len()).unwrap_or(0) >= 1 && s.received.get(&q2).map(|v| v.len()).unwrap_or(0) >= 1,
        "direct exchange routing",
    );
    assert_eq!(s.received.get(&q1), Some(&vec![b"for-q1".to_vec()]));
    assert_eq!(s.received.get(&q2), Some(&vec![b"for-q2".to_vec()]));
}

/// A fanout exchange ignores the routing key and delivers to every bound
/// queue (AMQP 0-9-1 §3.1.3.3).
#[test]
fn fanout_exchange_delivers_to_all_bound_queues() {
    let (host, port, user, pass) = broker_creds();
    let pid = std::process::id();
    let exchange = format!("hopf.amqp.integ.fanout.{pid}");
    let q1 = format!("hopf.amqp.integ.fanout.q1.{pid}");
    let q2 = format!("hopf.amqp.integ.fanout.q2.{pid}");

    let state = Arc::new(Mutex::new(ExchangeRoutingState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    let ex_for_publish = exchange.clone();
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(
            &rt,
            Arc::new(ExchangeRoutingFactory {
                exchange: exchange.clone(),
                exchange_type: "fanout",
                // Fanout ignores the binding key — any value (including empty) works.
                bindings: vec![(q1.clone(), String::new()), (q2.clone(), String::new())],
                state: Arc::clone(&state),
                publish: Arc::new(move |channel, client| {
                    client.basic_publish(channel, &ex_for_publish, "ignored", false, false, &BasicProperties::new(), b"broadcast");
                }),
            }),
        )
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.received.get(&q1).map(|v| v.len()).unwrap_or(0) >= 1 && s.received.get(&q2).map(|v| v.len()).unwrap_or(0) >= 1,
        "fanout exchange broadcast",
    );
    assert_eq!(s.received.get(&q1), Some(&vec![b"broadcast".to_vec()]));
    assert_eq!(s.received.get(&q2), Some(&vec![b"broadcast".to_vec()]));
}

/// A topic exchange matches `*` (exactly one word) and `#` (zero or more
/// words) wildcards in the binding key against the publish routing key
/// (AMQP 0-9-1 §3.1.3.4) — messages that match neither binding must not be
/// delivered anywhere.
#[test]
fn topic_exchange_wildcard_routing() {
    let (host, port, user, pass) = broker_creds();
    let pid = std::process::id();
    let exchange = format!("hopf.amqp.integ.topic.{pid}");
    let q1 = format!("hopf.amqp.integ.topic.q1.{pid}");
    let q2 = format!("hopf.amqp.integ.topic.q2.{pid}");

    let state = Arc::new(Mutex::new(ExchangeRoutingState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    let ex_for_publish = exchange.clone();
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(
            &rt,
            Arc::new(ExchangeRoutingFactory {
                exchange: exchange.clone(),
                exchange_type: "topic",
                bindings: vec![(q1.clone(), "orange.*".into()), (q2.clone(), "*.rabbit".into())],
                state: Arc::clone(&state),
                publish: Arc::new(move |channel, client| {
                    // Matches q1 only ("orange.*").
                    client.basic_publish(channel, &ex_for_publish, "orange.fox", false, false, &BasicProperties::new(), b"m1");
                    // Matches q2 only ("*.rabbit").
                    client.basic_publish(channel, &ex_for_publish, "lazy.rabbit", false, false, &BasicProperties::new(), b"m2");
                    // Matches neither binding.
                    client.basic_publish(channel, &ex_for_publish, "quick.fox", false, false, &BasicProperties::new(), b"m3");
                }),
            }),
        )
        .expect("connect");

    wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.received.get(&q1).map(|v| v.len()).unwrap_or(0) >= 1 && s.received.get(&q2).map(|v| v.len()).unwrap_or(0) >= 1,
        "topic exchange wildcard routing",
    );
    // Let anything mis-routed to the unmatched "quick.fox" case settle before
    // asserting exact counts — a real broker could conceivably still be
    // in-flight otherwise.
    thread::sleep(Duration::from_millis(200));
    let s = state.lock().unwrap().clone();
    assert_eq!(s.received.get(&q1), Some(&vec![b"m1".to_vec()]), "q1 must get exactly the orange.fox message");
    assert_eq!(s.received.get(&q2), Some(&vec![b"m2".to_vec()]), "q2 must get exactly the lazy.rabbit message");
}

#[derive(Default, Clone)]
struct ExchangeDeleteState {
    declared: bool,
    deleted: bool,
    channel_closed_code: Option<u16>,
    error: Option<String>,
}

struct ExchangeDeleteDriver {
    exchange: String,
    state: Arc<Mutex<ExchangeDeleteState>>,
    stage: u8,
}

impl AmqpClientDriver for ExchangeDeleteDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        if channel == 1 {
            client.exchange_declare(channel, &self.exchange, "fanout", false, false, true, false, &FieldTable::new());
        } else {
            // Second channel, opened after the exchange was deleted —
            // publishing to a gone exchange must close *this* channel with
            // 404 (NOT_FOUND), not tear down the whole connection.
            client.basic_publish(channel, &self.exchange, "", false, false, &BasicProperties::new(), b"should not route");
        }
    }

    fn on_channel_close(&mut self, client: &mut dyn AmqpClientControl, channel: u16, reply_code: u16, _: &str) {
        if channel == 2 {
            self.state.lock().unwrap().channel_closed_code = Some(reply_code);
            client.connection_close(200, "exchange delete integration done");
        }
    }

    fn on_exchange_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        self.state.lock().unwrap().declared = true;
        client.exchange_delete(channel, &self.exchange, false);
    }

    fn on_exchange_delete_ok(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        self.state.lock().unwrap().deleted = true;
        self.stage = 1;
        client.channel_open(2);
    }

    fn on_queue_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str, _: u32, _: u32) {}
    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}

    fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}
    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct ExchangeDeleteFactory {
    exchange: String,
    state: Arc<Mutex<ExchangeDeleteState>>,
}

impl AmqpClientHandlerFactory for ExchangeDeleteFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(ExchangeDeleteDriver {
            exchange: self.exchange.clone(),
            state: Arc::clone(&self.state),
            stage: 0,
        })
    }
}

/// `exchange.delete` actually removes the exchange from the broker — a
/// publish to it afterward is a publish to a nonexistent exchange, which
/// AMQP 0-9-1 defines as a channel-level exception (404 NOT_FOUND), not a
/// silently dropped message.
#[test]
fn exchange_delete_removes_routing() {
    let (host, port, user, pass) = broker_creds();
    let exchange = format!("hopf.amqp.integ.exdel.{}", std::process::id());

    let state = Arc::new(Mutex::new(ExchangeDeleteState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(ExchangeDeleteFactory { exchange, state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.channel_closed_code.is_some(),
        "exchange delete then publish-to-gone-exchange",
    );
    assert!(s.declared);
    assert!(s.deleted);
    assert_eq!(s.channel_closed_code, Some(404));
}

// ── Queue lifecycle ──────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct QueueUnbindState {
    delivered_before_unbind: bool,
    unbound: bool,
    got_empty_after_unbind: bool,
    error: Option<String>,
}

struct QueueUnbindDriver {
    exchange: String,
    queue: String,
    state: Arc<Mutex<QueueUnbindState>>,
}

impl AmqpClientDriver for QueueUnbindDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        // auto_delete=false: an auto-delete exchange is removed by the
        // broker as soon as its last binding goes away, which is exactly
        // what the queue_unbind below does — the test needs the exchange
        // to survive that so a *publish* to it (not a routing failure) is
        // what proves the binding is gone.
        client.exchange_declare(channel, &self.exchange, "fanout", false, false, false, false, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}

    fn on_exchange_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(channel, &self.queue, false, false, true, true, &FieldTable::new());
    }

    fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, queue: &str, _: u32, _: u32) {
        client.queue_bind(channel, queue, &self.exchange, "", &FieldTable::new());
        client.basic_consume(channel, queue, "", false, true, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, _: &str) {
        client.basic_publish(channel, &self.exchange, "", false, false, &BasicProperties::new(), b"before-unbind");
    }

    fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        self.state.lock().unwrap().delivered_before_unbind = true;
        client.queue_unbind(channel, &self.queue, &self.exchange, "", &FieldTable::new());
    }

    fn on_queue_unbind_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        self.state.lock().unwrap().unbound = true;
        client.basic_publish(channel, &self.exchange, "", false, false, &BasicProperties::new(), b"after-unbind");
        // No consumer path will fire for this one (the binding is gone) —
        // poll with basic.get instead, once the publish has had time to
        // reach the broker.
        thread::sleep(Duration::from_millis(200));
        client.basic_get(channel, &self.queue, true);
    }

    fn on_get_empty(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        self.state.lock().unwrap().got_empty_after_unbind = true;
        client.connection_close(200, "queue unbind integration done");
    }

    fn on_get_ok(
        &mut self,
        _: &mut dyn AmqpClientControl,
        _: u16,
        _: u64,
        _: bool,
        _: &str,
        _: &str,
        _: u32,
        _: &BasicProperties,
        _: u64,
    ) {
        self.state.lock().unwrap().error =
            Some("message still routed to the queue after queue.unbind".into());
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct QueueUnbindFactory {
    exchange: String,
    queue: String,
    state: Arc<Mutex<QueueUnbindState>>,
}

impl AmqpClientHandlerFactory for QueueUnbindFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(QueueUnbindDriver {
            exchange: self.exchange.clone(),
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
        })
    }
}

/// `queue.unbind` actually removes the binding — a message published after
/// unbinding must not reach the queue anymore.
#[test]
fn queue_unbind_stops_routing() {
    let (host, port, user, pass) = broker_creds();
    let pid = std::process::id();
    let exchange = format!("hopf.amqp.integ.unbind.{pid}");
    let queue = format!("hopf.amqp.integ.unbind.q.{pid}");

    let state = Arc::new(Mutex::new(QueueUnbindState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(QueueUnbindFactory { exchange, queue, state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.got_empty_after_unbind,
        "queue unbind stops routing",
    );
    assert!(s.delivered_before_unbind);
    assert!(s.unbound);
    assert!(s.got_empty_after_unbind);
}

#[derive(Default, Clone)]
struct QueuePurgeState {
    declared: bool,
    purged_count: Option<u32>,
    got_empty_after_purge: bool,
    error: Option<String>,
}

struct QueuePurgeDriver {
    queue: String,
    state: Arc<Mutex<QueuePurgeState>>,
}

impl AmqpClientDriver for QueuePurgeDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(channel, &self.queue, false, false, true, true, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, queue: &str, _: u32, _: u32) {
        self.state.lock().unwrap().declared = true;
        for i in 0..5 {
            client.basic_publish(
                channel, "", queue, false, false, &BasicProperties::new(),
                format!("purge-me-{i}").as_bytes(),
            );
        }
        // No publisher confirms on this channel — a fixed delay stands in
        // for "every publish has reached the broker" before purging.
        thread::sleep(Duration::from_millis(300));
        client.queue_purge(channel, queue);
    }

    fn on_queue_purge_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, message_count: u32) {
        self.state.lock().unwrap().purged_count = Some(message_count);
        client.basic_get(channel, &self.queue, true);
    }

    fn on_get_empty(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        self.state.lock().unwrap().got_empty_after_purge = true;
        client.connection_close(200, "queue purge integration done");
    }

    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}
    fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}
    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct QueuePurgeFactory {
    queue: String,
    state: Arc<Mutex<QueuePurgeState>>,
}

impl AmqpClientHandlerFactory for QueuePurgeFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(QueuePurgeDriver { queue: self.queue.clone(), state: Arc::clone(&self.state) })
    }
}

/// `queue.purge` drops every message currently sitting in the queue
/// (unconsumed, no active subscription) and reports how many it removed.
#[test]
fn queue_purge_clears_pending_messages() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.purge.{}", std::process::id());

    let state = Arc::new(Mutex::new(QueuePurgeState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(QueuePurgeFactory { queue, state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.got_empty_after_purge,
        "queue purge clears pending messages",
    );
    assert!(s.declared);
    assert_eq!(s.purged_count, Some(5));
    assert!(s.got_empty_after_purge);
}

// ── QoS / prefetch ───────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct QosState {
    /// How many deliveries had arrived by the time the *first* one was
    /// about to be acked — must be exactly 1 if `prefetch_count=1` is
    /// actually holding the broker back, not just a coincidence of timing.
    deliveries_when_first_acked: Option<u32>,
    total_delivered: u32,
    error: Option<String>,
}

struct QosDriver {
    queue: String,
    state: Arc<Mutex<QosState>>,
    deliveries_started: u32,
    pending_tag: Option<(u16, u64)>,
}

impl AmqpClientDriver for QosDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(channel, &self.queue, false, false, true, true, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, _: &str, _: u32, _: u32) {
        client.basic_qos(channel, 0, 1, false);
    }

    fn on_basic_qos_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        for i in 0..3 {
            client.basic_publish(
                channel, "", &self.queue, false, false, &BasicProperties::new(),
                format!("qos-{i}").as_bytes(),
            );
        }
        // No publisher confirms on this channel — a fixed delay stands in
        // for "every publish has reached the broker" before consuming.
        thread::sleep(Duration::from_millis(200));
        client.basic_consume(channel, &self.queue, "", false, false, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}

    fn on_delivery_start(
        &mut self,
        channel: u16,
        _consumer_tag: &str,
        delivery_tag: u64,
        _redelivered: bool,
        _exchange: &str,
        _routing_key: &str,
        _properties: &BasicProperties,
        _body_len: u64,
    ) {
        self.deliveries_started += 1;
        self.pending_tag = Some((channel, delivery_tag));
    }

    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        if self.deliveries_started == 1 {
            // Hold the ack back deliberately — if prefetch=1 is actually
            // enforced, nothing more should arrive during this window.
            thread::sleep(Duration::from_millis(300));
            self.state.lock().unwrap().deliveries_when_first_acked = Some(self.deliveries_started);
        }
        if let Some((ch, tag)) = self.pending_tag.take() {
            client.basic_ack(ch, tag, false);
        }
        self.state.lock().unwrap().total_delivered = self.deliveries_started;
        if self.deliveries_started == 3 {
            client.connection_close(200, "qos integration done");
        }
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct QosFactory {
    queue: String,
    state: Arc<Mutex<QosState>>,
}

impl AmqpClientHandlerFactory for QosFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(QosDriver {
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
            deliveries_started: 0,
            pending_tag: None,
        })
    }
}

/// `basic.qos(prefetch_count=1)` limits the broker to one unacknowledged
/// delivery at a time on the channel — publishing 3 messages ahead of the
/// consumer must not push all 3 at once.
#[test]
fn basic_qos_prefetch_count_limits_in_flight_deliveries() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.qos.{}", std::process::id());

    let state = Arc::new(Mutex::new(QosState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(QosFactory { queue, state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.total_delivered == 3,
        "basic.qos prefetch_count=1 limits in-flight deliveries",
    );
    assert_eq!(
        s.deliveries_when_first_acked,
        Some(1),
        "prefetch_count=1 must hold back further deliveries until the first is acked"
    );
}

// ── Negative acknowledgement ─────────────────────────────────────────────────

#[derive(Default, Clone)]
struct NackState {
    first_redelivered: Option<bool>,
    second_redelivered: Option<bool>,
    error: Option<String>,
}

struct NackDriver {
    queue: String,
    state: Arc<Mutex<NackState>>,
    deliveries: u32,
    pending_tag: Option<u64>,
}

impl AmqpClientDriver for NackDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(channel, &self.queue, false, false, true, true, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, queue: &str, _: u32, _: u32) {
        client.basic_publish(channel, "", queue, false, false, &BasicProperties::new(), b"nack-me");
        client.basic_consume(channel, queue, "", false, false, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}

    fn on_delivery_start(
        &mut self,
        _channel: u16,
        _consumer_tag: &str,
        delivery_tag: u64,
        redelivered: bool,
        _exchange: &str,
        _routing_key: &str,
        _properties: &BasicProperties,
        _body_len: u64,
    ) {
        self.deliveries += 1;
        self.pending_tag = Some(delivery_tag);
        let mut s = self.state.lock().unwrap();
        if self.deliveries == 1 {
            s.first_redelivered = Some(redelivered);
        } else {
            s.second_redelivered = Some(redelivered);
        }
    }

    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let Some(tag) = self.pending_tag.take() else { return };
        if self.deliveries == 1 {
            // RabbitMQ extension: nack(requeue=true) puts the message back
            // for redelivery, same effect as basic.reject(requeue=true)
            // but supports `multiple`.
            client.basic_nack(channel, tag, false, true);
        } else {
            client.connection_close(200, "nack integration done");
        }
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct NackFactory {
    queue: String,
    state: Arc<Mutex<NackState>>,
}

impl AmqpClientHandlerFactory for NackFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(NackDriver {
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
            deliveries: 0,
            pending_tag: None,
        })
    }
}

/// `basic.nack(requeue=true)` (RabbitMQ extension) puts the message back on
/// the queue for redelivery, same as `basic.reject(requeue=true)`.
#[test]
fn basic_nack_requeue_redelivers() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.nack.{}", std::process::id());

    let state = Arc::new(Mutex::new(NackState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(NackFactory { queue, state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.second_redelivered.is_some(),
        "basic.nack requeue redelivery",
    );
    assert_eq!(s.first_redelivered, Some(false));
    assert_eq!(s.second_redelivered, Some(true));
}

#[derive(Default, Clone)]
struct RejectState {
    delivered: bool,
    rejected: bool,
    got_empty_after_reject: bool,
    error: Option<String>,
}

struct RejectDriver {
    queue: String,
    state: Arc<Mutex<RejectState>>,
    pending_tag: Option<u64>,
}

impl AmqpClientDriver for RejectDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(channel, &self.queue, false, false, true, true, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, queue: &str, _: u32, _: u32) {
        client.basic_publish(channel, "", queue, false, false, &BasicProperties::new(), b"reject-me");
        client.basic_consume(channel, queue, "", false, false, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}

    fn on_delivery_start(&mut self, _: u16, _: &str, delivery_tag: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {
        self.pending_tag = Some(delivery_tag);
        self.state.lock().unwrap().delivered = true;
    }

    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let Some(tag) = self.pending_tag.take() else { return };
        self.state.lock().unwrap().rejected = true;
        client.basic_reject(channel, tag, false);
        // No further reply to basic.reject — poll with basic.get to prove
        // the queue really did end up empty (not redelivered).
        thread::sleep(Duration::from_millis(200));
        client.basic_get(channel, &self.queue, true);
    }

    fn on_get_empty(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        self.state.lock().unwrap().got_empty_after_reject = true;
        client.connection_close(200, "reject integration done");
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct RejectFactory {
    queue: String,
    state: Arc<Mutex<RejectState>>,
}

impl AmqpClientHandlerFactory for RejectFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(RejectDriver { queue: self.queue.clone(), state: Arc::clone(&self.state), pending_tag: None })
    }
}

/// `basic.reject(requeue=false)` drops the message — it must not come back.
#[test]
fn basic_reject_no_requeue_drops_message() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.reject.{}", std::process::id());

    let state = Arc::new(Mutex::new(RejectState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(RejectFactory { queue, state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.got_empty_after_reject,
        "basic.reject(requeue=false) drops the message",
    );
    assert!(s.delivered);
    assert!(s.rejected);
    assert!(s.got_empty_after_reject);
}

// ── Mandatory publish / basic.return ─────────────────────────────────────────

#[derive(Default, Clone)]
struct MandatoryReturnState {
    declared: bool,
    return_reply_code: Option<u16>,
    return_routing_key: Option<String>,
    returned_body: Vec<u8>,
    return_complete: bool,
    error: Option<String>,
}

struct MandatoryReturnDriver {
    exchange: String,
    state: Arc<Mutex<MandatoryReturnState>>,
}

impl AmqpClientDriver for MandatoryReturnDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.exchange_declare(channel, &self.exchange, "direct", false, false, true, false, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}

    fn on_exchange_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        self.state.lock().unwrap().declared = true;
        // No bindings at all — a mandatory publish here is unroutable by
        // construction, whatever the routing key.
        client.basic_publish(
            channel, &self.exchange, "nobody.listens", true, false,
            &BasicProperties::new(), b"mandatory-unroutable",
        );
    }

    fn on_return_start(
        &mut self,
        _channel: u16,
        reply_code: u16,
        _reply_text: &str,
        _exchange: &str,
        routing_key: &str,
        _properties: &BasicProperties,
        _body_len: u64,
    ) {
        let mut s = self.state.lock().unwrap();
        s.return_reply_code = Some(reply_code);
        s.return_routing_key = Some(routing_key.to_string());
    }

    fn on_return_data(&mut self, _channel: u16, data: &[u8]) {
        self.state.lock().unwrap().returned_body.extend_from_slice(data);
    }

    fn on_return_complete(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        self.state.lock().unwrap().return_complete = true;
        client.connection_close(200, "mandatory return integration done");
    }

    fn on_queue_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str, _: u32, _: u32) {}
    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}
    fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}
    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct MandatoryReturnFactory {
    exchange: String,
    state: Arc<Mutex<MandatoryReturnState>>,
}

impl AmqpClientHandlerFactory for MandatoryReturnFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(MandatoryReturnDriver { exchange: self.exchange.clone(), state: Arc::clone(&self.state) })
    }
}

/// `basic.publish(mandatory=true)` to a routing key with no matching
/// binding must come back as `basic.return` (reply-code 312, NO_ROUTE)
/// with the original message content, not be silently dropped.
#[test]
fn mandatory_publish_unroutable_triggers_basic_return() {
    let (host, port, user, pass) = broker_creds();
    let exchange = format!("hopf.amqp.integ.mandatory.{}", std::process::id());

    let state = Arc::new(Mutex::new(MandatoryReturnState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(MandatoryReturnFactory { exchange, state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.return_complete,
        "mandatory publish triggers basic.return",
    );
    assert!(s.declared);
    assert_eq!(s.return_reply_code, Some(312), "expected NO_ROUTE");
    assert_eq!(s.return_routing_key.as_deref(), Some("nobody.listens"));
    assert_eq!(s.returned_body, b"mandatory-unroutable");
}

// ── Broker-initiated consumer cancellation ───────────────────────────────────

#[derive(Default, Clone)]
struct ConsumerCancelState {
    consuming: bool,
    cancelled_tag: Option<String>,
    error: Option<String>,
}

struct ConsumerCancelDriver {
    queue: String,
    state: Arc<Mutex<ConsumerCancelState>>,
}

impl AmqpClientDriver for ConsumerCancelDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        // durable=true, exclusive=false: a second connection needs to be
        // able to see and delete this queue out from under the consumer.
        // RabbitMQ 4.x deprecated (and by default refuses) the transient
        // *and* non-exclusive combination — declaring it durable sidesteps
        // that without changing what this test is actually about.
        client.queue_declare(channel, &self.queue, false, true, false, false, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, queue: &str, _: u32, _: u32) {
        client.basic_consume(channel, queue, "", false, true, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {
        self.state.lock().unwrap().consuming = true;
    }

    fn on_consumer_cancelled(&mut self, client: &mut dyn AmqpClientControl, _channel: u16, consumer_tag: &str) {
        self.state.lock().unwrap().cancelled_tag = Some(consumer_tag.to_string());
        client.connection_close(200, "consumer cancel integration done");
    }

    fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}
    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct ConsumerCancelFactory {
    queue: String,
    state: Arc<Mutex<ConsumerCancelState>>,
}

impl AmqpClientHandlerFactory for ConsumerCancelFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(ConsumerCancelDriver { queue: self.queue.clone(), state: Arc::clone(&self.state) })
    }
}

#[derive(Default, Clone)]
struct DeleterState {
    deleted: bool,
    error: Option<String>,
}

struct DeleterDriver {
    queue: String,
    state: Arc<Mutex<DeleterState>>,
}

impl AmqpClientDriver for DeleterDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_delete(channel, &self.queue, false, false);
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}
    fn on_queue_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str, _: u32, _: u32) {}
    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}

    fn on_queue_delete_ok(&mut self, client: &mut dyn AmqpClientControl, _channel: u16, _message_count: u32) {
        self.state.lock().unwrap().deleted = true;
        client.connection_close(200, "deleter integration done");
    }

    fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}
    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct DeleterFactory {
    queue: String,
    state: Arc<Mutex<DeleterState>>,
}

impl AmqpClientHandlerFactory for DeleterFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(DeleterDriver { queue: self.queue.clone(), state: Arc::clone(&self.state) })
    }
}

/// RabbitMQ's `consumer_cancel_notify` extension: when a queue a consumer
/// is attached to is deleted out from under it (here, by a *second*
/// connection), the broker tells the consumer via `basic.cancel` instead
/// of just silently going quiet.
#[test]
fn consumer_cancel_notify_on_queue_deleted_externally() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.cancel.{}", std::process::id());

    let consumer_state = Arc::new(Mutex::new(ConsumerCancelState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host.clone(), port)
        .credentials(user.clone(), pass.clone())
        .connect(
            &rt,
            Arc::new(ConsumerCancelFactory { queue: queue.clone(), state: Arc::clone(&consumer_state) }),
        )
        .expect("connect (consumer)");

    wait_for(
        &consumer_state,
        15,
        |s| &s.error,
        |s| s.consuming,
        "consumer attached before the deleting connection starts",
    );

    let deleter_state = Arc::new(Mutex::new(DeleterState::default()));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(DeleterFactory { queue, state: Arc::clone(&deleter_state) }))
        .expect("connect (deleter)");

    wait_for(&deleter_state, 15, |s| &s.error, |s| s.deleted, "queue deleted from the second connection");

    let s = wait_for(
        &consumer_state,
        15,
        |s| &s.error,
        |s| s.cancelled_tag.is_some(),
        "consumer_cancel_notify after external queue deletion",
    );
    assert!(s.cancelled_tag.is_some());
}

// ── Message properties round-trip ────────────────────────────────────────────

#[derive(Default, Clone)]
struct PropertiesState {
    received: Option<BasicProperties>,
    error: Option<String>,
}

struct PropertiesDriver {
    queue: String,
    sent: BasicProperties,
    state: Arc<Mutex<PropertiesState>>,
}

impl AmqpClientDriver for PropertiesDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(channel, &self.queue, false, false, true, true, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, queue: &str, _: u32, _: u32) {
        client.basic_publish(channel, "", queue, false, false, &self.sent, b"props-body");
        client.basic_consume(channel, queue, "", false, true, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}

    fn on_delivery_start(
        &mut self,
        _channel: u16,
        _consumer_tag: &str,
        _delivery_tag: u64,
        _redelivered: bool,
        _exchange: &str,
        _routing_key: &str,
        properties: &BasicProperties,
        _body_len: u64,
    ) {
        self.state.lock().unwrap().received = Some(properties.clone());
    }

    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        client.connection_close(200, "properties round-trip integration done");
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct PropertiesFactory {
    queue: String,
    sent: BasicProperties,
    state: Arc<Mutex<PropertiesState>>,
}

impl AmqpClientHandlerFactory for PropertiesFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(PropertiesDriver {
            queue: self.queue.clone(),
            sent: self.sent.clone(),
            state: Arc::clone(&self.state),
        })
    }
}

/// Every `BasicProperties` field survives a publish → consume round trip
/// unchanged (AMQP 0-9-1 §1.9.1, `basic` content class properties).
#[test]
fn message_properties_round_trip() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.props.{}", std::process::id());

    let mut headers = FieldTable::new();
    headers.insert("x-hopf-str".into(), FieldValue::longstr("value"));
    headers.insert("x-hopf-int".into(), FieldValue::I32(42));
    headers.insert("x-hopf-bool".into(), FieldValue::Bool(true));

    let mut sent = BasicProperties::new();
    sent.content_type = Some("application/octet-stream".into());
    sent.content_encoding = Some("identity".into());
    sent.headers = Some(headers);
    sent.delivery_mode = Some(2); // persistent
    sent.priority = Some(4);
    sent.correlation_id = Some("corr-123".into());
    sent.reply_to = Some("reply.queue".into());
    sent.expiration = Some("60000".into());
    sent.message_id = Some("msg-abc".into());
    sent.timestamp = Some(1_700_000_000);
    sent.message_type = Some("hopf.test.message".into());
    // RabbitMQ validates a publish's `user_id` property against the
    // connection's authenticated identity by default — it must be
    // "guest" here (the same as `broker_creds()`'s default), or the
    // publish is refused (403 ACCESS_REFUSED) instead of round-tripped.
    sent.user_id = Some(user.clone());
    sent.app_id = Some("hopf-amqp-integration-test".into());

    let state = Arc::new(Mutex::new(PropertiesState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(PropertiesFactory { queue, sent: sent.clone(), state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.received.is_some(),
        "message properties round-trip",
    );
    assert_eq!(s.received, Some(sent));
}

// ── Message TTL ──────────────────────────────────────────────────────────────

// The publish and the eventual `basic.get` are done on two *separate*
// connections (rather than one connection with a `thread::sleep` in
// between) because a driver callback runs on the reactor thread: sleeping
// inside it would just delay flushing the outgoing `basic.publish` frame
// to the socket, so the broker's TTL clock wouldn't actually start until
// the sleep was already over. Sleeping on the *test* thread between two
// independent connections guarantees the message has genuinely been
// sitting on the broker past its TTL before the get is even sent.
#[derive(Default, Clone)]
struct TtlState {
    declared: bool,
    published: bool,
    got_empty: bool,
    got_unexpected_message: bool,
    error: Option<String>,
}

struct TtlPublisherDriver {
    queue: String,
    state: Arc<Mutex<TtlState>>,
}

impl AmqpClientDriver for TtlPublisherDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let mut args = FieldTable::new();
        // Queue-level TTL (RabbitMQ extension, `x-message-ttl`): every
        // message on this queue expires after 200ms, whether or not
        // anyone ever reads it. durable=true, exclusive=false so the
        // queue survives this connection closing — the getter connection
        // needs to see it later.
        args.insert("x-message-ttl".into(), FieldValue::I32(200));
        client.queue_declare(channel, &self.queue, false, true, false, false, &args);
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, queue: &str, _: u32, _: u32) {
        let mut s = self.state.lock().unwrap();
        s.declared = true;
        s.published = true;
        drop(s);
        client.basic_publish(channel, "", queue, false, false, &BasicProperties::new(), b"expire-me");
        client.connection_close(200, "ttl publisher done");
    }

    fn on_get_empty(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}
    #[allow(clippy::too_many_arguments)]
    fn on_get_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u64, _: bool, _: &str, _: &str, _: u32, _: &BasicProperties, _: u64) {}

    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}
    fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}
    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct TtlPublisherFactory {
    queue: String,
    state: Arc<Mutex<TtlState>>,
}

impl AmqpClientHandlerFactory for TtlPublisherFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(TtlPublisherDriver { queue: self.queue.clone(), state: Arc::clone(&self.state) })
    }
}

struct TtlGetterDriver {
    queue: String,
    state: Arc<Mutex<TtlState>>,
}

impl AmqpClientDriver for TtlGetterDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.basic_get(channel, &self.queue, true);
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}
    fn on_queue_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str, _: u32, _: u32) {}

    fn on_get_empty(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        self.state.lock().unwrap().got_empty = true;
        // The TTL'd message expired before we ever consumed it, so there's
        // nothing left to clean up but the queue itself.
        client.queue_delete(channel, &self.queue, false, false);
        client.connection_close(200, "ttl getter done");
    }

    #[allow(clippy::too_many_arguments)]
    fn on_get_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, _: u64, _: bool, _: &str, _: &str, _: u32, _: &BasicProperties, _: u64) {
        self.state.lock().unwrap().got_unexpected_message = true;
        client.queue_delete(channel, &self.queue, false, false);
        client.connection_close(200, "ttl getter done");
    }

    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}
    fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}
    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct TtlGetterFactory {
    queue: String,
    state: Arc<Mutex<TtlState>>,
}

impl AmqpClientHandlerFactory for TtlGetterFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(TtlGetterDriver { queue: self.queue.clone(), state: Arc::clone(&self.state) })
    }
}

/// A queue with `x-message-ttl` set (RabbitMQ extension) drops a message
/// that sits unconsumed past the TTL — it must never be delivered.
#[test]
fn message_ttl_expires_before_delivery() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.ttl.{}", std::process::id());

    let state = Arc::new(Mutex::new(TtlState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host.clone(), port)
        .credentials(user.clone(), pass.clone())
        .connect(&rt, Arc::new(TtlPublisherFactory { queue: queue.clone(), state: Arc::clone(&state) }))
        .expect("connect publisher");

    wait_for(&state, 15, |s| &s.error, |s| s.published, "ttl publish");

    // Real wall-clock wait, on the test thread, well past the queue's
    // 200ms TTL — the publisher connection is already closed by now, so
    // this is genuinely waiting on the broker's own expiry, not on
    // anything this client is doing.
    thread::sleep(Duration::from_millis(700));

    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(TtlGetterFactory { queue, state: Arc::clone(&state) }))
        .expect("connect getter");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.got_empty || s.got_unexpected_message,
        "message ttl expiry",
    );
    assert!(s.declared);
    assert!(s.published);
    assert!(!s.got_unexpected_message, "message was still present after its TTL elapsed");
    assert!(s.got_empty);
}

// ── Multi-channel isolation ─────────────────────────────────────────────────

#[derive(Default, Clone)]
struct MultiChannelState {
    // channel -> received bodies, in delivery order.
    received: std::collections::HashMap<u16, Vec<Vec<u8>>>,
    consuming: std::collections::HashMap<u16, bool>,
    error: Option<String>,
}

struct MultiChannelDriver {
    // channel -> queue name.
    queues: std::collections::HashMap<u16, String>,
    state: Arc<Mutex<MultiChannelState>>,
}

impl AmqpClientDriver for MultiChannelDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        for &channel in self.queues.keys() {
            client.channel_open(channel);
        }
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        let queue = self.queues.get(&channel).expect("known channel").clone();
        client.queue_declare(channel, &queue, false, false, true, true, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, queue: &str, _: u32, _: u32) {
        client.basic_consume(channel, queue, queue, false, true, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, _: &str) {
        let both_ready = {
            let mut s = self.state.lock().unwrap();
            s.consuming.insert(channel, true);
            self.queues.keys().all(|c| s.consuming.get(c).copied().unwrap_or(false))
        };
        if !both_ready {
            return;
        }
        // Both consumers are attached — publish interleaved across both
        // channels from right here (a driver callback on the reactor
        // thread is the only place commands can be issued from).
        let q1 = self.queues.get(&1).expect("channel 1 queue").clone();
        let q2 = self.queues.get(&2).expect("channel 2 queue").clone();
        for i in 0..3u32 {
            client.basic_publish(1, "", &q1, false, false, &BasicProperties::new(), format!("ch1-{i}").as_bytes());
            client.basic_publish(2, "", &q2, false, false, &BasicProperties::new(), format!("ch2-{i}").as_bytes());
        }
    }

    fn on_delivery_start(
        &mut self,
        _channel: u16,
        _consumer_tag: &str,
        _delivery_tag: u64,
        _redelivered: bool,
        _exchange: &str,
        _routing_key: &str,
        _properties: &BasicProperties,
        _body_len: u64,
    ) {
    }

    fn on_delivery_data(&mut self, channel: u16, data: &[u8]) {
        self.state
            .lock()
            .unwrap()
            .received
            .entry(channel)
            .or_default()
            .push(data.to_vec());
    }

    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_get_empty(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}
    #[allow(clippy::too_many_arguments)]
    fn on_get_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u64, _: bool, _: &str, _: &str, _: u32, _: &BasicProperties, _: u64) {}

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct MultiChannelFactory {
    queues: std::collections::HashMap<u16, String>,
    state: Arc<Mutex<MultiChannelState>>,
}

impl AmqpClientHandlerFactory for MultiChannelFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(MultiChannelDriver { queues: self.queues.clone(), state: Arc::clone(&self.state) })
    }
}

/// Two channels on the same connection, each with its own consumer, must
/// never see each other's deliveries — the real-broker counterpart of the
/// interleaved-frame codec unit test added for issue #180.
#[test]
fn two_channels_one_connection_do_not_cross_talk() {
    let (host, port, user, pass) = broker_creds();
    let pid = std::process::id();
    let q1 = format!("hopf.amqp.integ.multi.1.{pid}");
    let q2 = format!("hopf.amqp.integ.multi.2.{pid}");

    let mut queues = std::collections::HashMap::new();
    queues.insert(1u16, q1.clone());
    queues.insert(2u16, q2.clone());

    let state = Arc::new(Mutex::new(MultiChannelState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(MultiChannelFactory { queues, state: Arc::clone(&state) }))
        .expect("connect");

    // The driver itself publishes the interleaved messages once both
    // channels' consumers are attached (see `on_consume_ok` above).
    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| {
            s.received.get(&1).map(|v| v.len()).unwrap_or(0) >= 3
                && s.received.get(&2).map(|v| v.len()).unwrap_or(0) >= 3
        },
        "interleaved deliveries on both channels",
    );

    let ch1 = s.received.get(&1).cloned().unwrap_or_default();
    let ch2 = s.received.get(&2).cloned().unwrap_or_default();
    assert_eq!(ch1.len(), 3);
    assert_eq!(ch2.len(), 3);
    for (i, body) in ch1.iter().enumerate() {
        assert_eq!(body, format!("ch1-{i}").as_bytes());
    }
    for (i, body) in ch2.iter().enumerate() {
        assert_eq!(body, format!("ch2-{i}").as_bytes());
    }
}

// ── Authentication failure ──────────────────────────────────────────────────

#[derive(Default, Clone)]
struct AuthFailureState {
    close_code: Option<u16>,
    close_text: Option<String>,
    error: Option<String>,
    disconnected: bool,
}

struct AuthFailureDriver {
    state: Arc<Mutex<AuthFailureState>>,
}

impl AmqpClientDriver for AuthFailureDriver {
    fn on_connection_open(&mut self, _: &mut dyn AmqpClientControl) {}
    fn on_channel_open(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}
    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}
    fn on_queue_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str, _: u32, _: u32) {}
    fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}
    fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}
    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_connection_close(&mut self, reply_code: u16, reply_text: &str) {
        let mut s = self.state.lock().unwrap();
        s.close_code = Some(reply_code);
        s.close_text = Some(reply_text.to_string());
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {
        self.state.lock().unwrap().disconnected = true;
    }
}

struct AuthFailureFactory {
    state: Arc<Mutex<AuthFailureState>>,
}

impl AmqpClientHandlerFactory for AuthFailureFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(AuthFailureDriver { state: Arc::clone(&self.state) })
    }
}

/// A connection attempt with a wrong password must fail promptly — either
/// synchronously from `connect()`, or via `on_connection_close`/`on_error`/
/// `on_disconnected` shortly after — rather than hanging as if the
/// handshake were still in progress.
#[test]
fn wrong_credentials_closes_connection_promptly() {
    let (host, port, user, _pass) = broker_creds();

    let state = Arc::new(Mutex::new(AuthFailureState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    let connect_result = AmqpClient::new(host, port)
        .credentials(user, "definitely-not-the-right-password")
        .connect(&rt, Arc::new(AuthFailureFactory { state: Arc::clone(&state) }));

    if connect_result.is_err() {
        // Failed synchronously — that's a prompt failure too.
        return;
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let s = state.lock().unwrap().clone();
        if s.close_code.is_some() || s.error.is_some() || s.disconnected {
            if let Some(code) = s.close_code {
                // RabbitMQ's authentication_failure_close capability
                // reports this as a connection-level exception rather
                // than a bare TCP drop.
                assert!(
                    code == 403 || code == 530,
                    "unexpected close code for bad credentials: {code} (text: {:?})",
                    s.close_text
                );
            }
            return;
        }
        if Instant::now() >= deadline {
            panic!("wrong credentials did not close the connection promptly");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

// ── Large non-streaming publish ─────────────────────────────────────────────

#[derive(Default, Clone)]
struct LargePublishState {
    body_matches: Option<bool>,
    error: Option<String>,
}

struct LargePublishDriver {
    queue: String,
    state: Arc<Mutex<LargePublishState>>,
    expected_body: Vec<u8>,
    received: Vec<u8>,
}

impl AmqpClientDriver for LargePublishDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.queue_declare(channel, &self.queue, false, false, true, true, &FieldTable::new());
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
    fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, queue: &str, _: u32, _: u32) {
        client.basic_consume(channel, queue, "", false, true, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, _: &str) {
        let mut props = BasicProperties::new();
        props.content_type = Some("application/octet-stream".into());
        // A single non-streaming basic_publish call with a body bigger
        // than any reasonable negotiated frame_max — the non-streaming
        // path (unlike basic_publish_start/basic_publish_body) has to do
        // its own internal content-frame splitting in one shot.
        client.basic_publish(channel, "", &self.queue, false, false, &props, &self.expected_body);
    }

    fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, body_len: u64) {
        self.received = Vec::with_capacity(body_len as usize);
    }

    fn on_delivery_data(&mut self, _channel: u16, data: &[u8]) {
        self.received.extend_from_slice(data);
    }

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        self.state.lock().unwrap().body_matches = Some(self.received == self.expected_body);
        client.connection_close(200, "large publish integration done");
    }

    fn on_get_empty(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}
    #[allow(clippy::too_many_arguments)]
    fn on_get_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u64, _: bool, _: &str, _: &str, _: u32, _: &BasicProperties, _: u64) {}

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct LargePublishFactory {
    queue: String,
    state: Arc<Mutex<LargePublishState>>,
}

impl AmqpClientHandlerFactory for LargePublishFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(LargePublishDriver {
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
            // Deliberately larger than any reasonable frame_max, exercising
            // the *non-streaming* basic_publish's internal content-frame
            // splitting (the streaming path is already covered by
            // streaming_publish_reassembles_to_original_bytes above).
            expected_body: test_body(200_000),
            received: Vec::new(),
        })
    }
}

/// A single `basic_publish` call (not the streaming `basic_publish_start`/
/// `basic_publish_body` pair) with a body larger than the broker's
/// negotiated `frame_max` must still round-trip byte-for-byte — the
/// non-streaming path has to split content frames internally too.
#[test]
fn basic_publish_body_larger_than_frame_max_splits_correctly() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp.integ.large.{}", std::process::id());

    let state = Arc::new(Mutex::new(LargePublishState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(LargePublishFactory { queue, state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        20,
        |s| &s.error,
        |s| s.body_matches.is_some(),
        "large non-streaming publish round-trip",
    );
    assert_eq!(s.body_matches, Some(true));
}

// ── Recovery across two channels ────────────────────────────────────────────

#[derive(Default, Clone)]
struct MultiChannelRecoveryState {
    first_consume_ok: bool,
    recovered: bool,
    redelivered_after_recovery: bool,
    error: Option<String>,
}

struct MultiChannelRecoveryDriver {
    exchange: String,
    queue: String,
    state: Arc<Mutex<MultiChannelRecoveryState>>,
    consume_ok_count: u32,
    // Set once the initial exchange→queue→bind→consume chain has been
    // driven through to completion. On reconnect, `Topology::replay`
    // reproduces the whole chain by itself from the raw client — it does
    // *not* go through `on_channel_open`/`on_connection_open` again, but
    // the broker acks it produces (exchange.declare-ok, queue.declare-ok,
    // queue.bind-ok) still land on this same driver's ack handlers. Without
    // this guard those handlers would react to replay's acks by re-issuing
    // the same chaining calls (e.g. re-opening an already-open channel 2),
    // which is both redundant and a protocol violation.
    setup_complete: bool,
}

impl AmqpClientDriver for MultiChannelRecoveryDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        if channel == 1 {
            // Exchange declared on channel 1...
            client.exchange_declare(channel, &self.exchange, "fanout", false, false, true, false, &FieldTable::new());
        } else {
            // ...queue declared on channel 2, bound to it below. Topology
            // replay after reconnect must reproduce the exchange (on
            // channel 1) before the binding (on channel 2) references it,
            // even though they're on different channels.
            client.queue_declare(channel, &self.queue, false, false, true, true, &FieldTable::new());
        }
    }

    fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}

    fn on_exchange_declare_ok(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        if self.setup_complete {
            return;
        }
        client.channel_open(2);
    }

    fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, queue: &str, _: u32, _: u32) {
        if self.setup_complete {
            return;
        }
        client.queue_bind(channel, queue, &self.exchange, "", &FieldTable::new());
    }

    fn on_queue_bind_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        if self.setup_complete {
            return;
        }
        client.basic_consume(channel, &self.queue, "", false, true, false, &FieldTable::new());
    }

    fn on_consume_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, _: &str) {
        self.consume_ok_count += 1;
        if self.consume_ok_count == 1 {
            // Mark first success, then simulate an unexpected drop —
            // indistinguishable to AmqpRecoveringClient from a real broker
            // restart, so it reconnects and replays exchange + queue +
            // binding + consumer across both channels on its own. Nothing
            // in this driver needs to drive that replay along — mark setup
            // complete so the ack handlers above go quiet for the rest of
            // this driver instance's life.
            self.setup_complete = true;
            self.state.lock().unwrap().first_consume_ok = true;
            client.connection_close(200, "integration test induced disconnect");
        } else {
            // Reconnect replayed the full topology across both channels —
            // publish to the exchange (fanout, so no routing key needed)
            // and confirm it still reaches the queue bound to it.
            let mut props = BasicProperties::new();
            props.content_type = Some("text/plain".into());
            client.basic_publish(channel, &self.exchange, "", false, false, &props, b"post-recovery");
        }
    }

    fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
    fn on_delivery_data(&mut self, _: u16, _: &[u8]) {}

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, _channel: u16) {
        self.state.lock().unwrap().redelivered_after_recovery = true;
        client.connection_close(200, "multi-channel recovery integration done");
    }

    fn on_error(&mut self, err: &io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct MultiChannelRecoveryFactory {
    exchange: String,
    queue: String,
    state: Arc<Mutex<MultiChannelRecoveryState>>,
}

impl AmqpClientHandlerFactory for MultiChannelRecoveryFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(MultiChannelRecoveryDriver {
            exchange: self.exchange.clone(),
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
            consume_ok_count: 0,
            setup_complete: false,
        })
    }
}

struct MultiChannelRecoveryListenerCapture {
    state: Arc<Mutex<MultiChannelRecoveryState>>,
}

impl RecoveryListener for MultiChannelRecoveryListenerCapture {
    fn on_recovered(&self) {
        self.state.lock().unwrap().recovered = true;
    }
}

/// Deepens issue #196/#208's recovery coverage (previously only unit-tested
/// against a mock `TrackingControl`) against a *real* broker, and spans two
/// channels: an exchange declared on channel 1 with a queue bound to it on
/// channel 2. After an induced disconnect, `AmqpRecoveringClient` must
/// replay the exchange before the binding that references it, even though
/// they're on different channels, and the post-recovery publish must still
/// route through to the queue.
#[test]
fn recovering_client_replays_exchange_and_binding_across_channels() {
    let (host, port, user, pass) = broker_creds();
    let pid = std::process::id();
    let exchange = format!("hopf.amqp.integ.recovery.mc.ex.{pid}");
    let queue = format!("hopf.amqp.integ.recovery.mc.q.{pid}");

    let state = Arc::new(Mutex::new(MultiChannelRecoveryState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    let handle =
        AmqpRecoveringClient::new(AmqpClient::new(host, port).credentials(user, pass), Arc::clone(&rt))
            .recovery_listener(Arc::new(MultiChannelRecoveryListenerCapture { state: Arc::clone(&state) }))
            .connect(Arc::new(MultiChannelRecoveryFactory { exchange, queue, state: Arc::clone(&state) }))
            .expect("connect");

    let s = wait_for(
        &state,
        20,
        |s| &s.error,
        |s| s.redelivered_after_recovery,
        "reconnect + cross-channel topology replay + post-recovery delivery",
    );
    assert!(s.first_consume_ok);
    assert!(s.recovered, "RecoveryListener::on_recovered must fire");
    assert!(s.redelivered_after_recovery);
    handle.close();
}
