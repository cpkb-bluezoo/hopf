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

#[derive(Default)]
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

#[test]
fn publish_consume_roundtrip() {
    let host = std::env::var("HOPF_AMQP_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("HOPF_AMQP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5672);
    let user = std::env::var("HOPF_AMQP_USER").unwrap_or_else(|_| "guest".into());
    let pass = std::env::var("HOPF_AMQP_PASS").unwrap_or_else(|_| "guest".into());
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

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        {
            let s = state.lock().unwrap();
            if let Some(ref e) = s.error {
                panic!("amqp error: {e}");
            }
            if s.delivered && s.acked_pub {
                break;
            }
        }
        if Instant::now() > deadline {
            let s = state.lock().unwrap();
            panic!(
                "timeout waiting for round-trip (opened={} declared={} consumed={} published={} delivered={} acked={})",
                s.opened, s.declared, s.consumed, s.published, s.delivered, s.acked_pub
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}
