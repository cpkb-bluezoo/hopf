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
};
use crate::codec::{BasicProperties, FieldTable};

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

    fn on_delivery_data(&mut self, _: &[u8]) {}

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

    fn on_delivery_data(&mut self, _: &[u8]) {}

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

    fn on_delivery_data(&mut self, _: &[u8]) {}

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

    fn on_delivery_data(&mut self, _: &[u8]) {}

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
    paused_ack: Option<bool>,
    resumed_ack: Option<bool>,
    error: Option<String>,
}

struct FlowDriver {
    state: Arc<Mutex<FlowState>>,
    step: u8,
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

    fn on_delivery_data(&mut self, _: &[u8]) {}

    fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}

    fn on_flow_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, active: bool) {
        let mut s = self.state.lock().unwrap();
        if self.step == 0 {
            s.paused_ack = Some(active);
            self.step = 1;
            drop(s);
            client.flow(channel, true);
        } else {
            s.resumed_ack = Some(active);
            drop(s);
            client.connection_close(200, "flow integration done");
        }
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
        Box::new(FlowDriver {
            state: Arc::clone(&self.state),
            step: 0,
        })
    }
}

#[test]
fn client_initiated_flow_roundtrip() {
    let (host, port, user, pass) = broker_creds();

    let state = Arc::new(Mutex::new(FlowState::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    AmqpClient::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(FlowFactory { state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(
        &state,
        15,
        |s| &s.error,
        |s| s.resumed_ack.is_some(),
        "channel.flow pause/resume",
    );
    assert_eq!(s.paused_ack, Some(false));
    assert_eq!(s.resumed_ack, Some(true));
}
