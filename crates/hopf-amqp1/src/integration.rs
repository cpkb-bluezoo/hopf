// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in AMQP 1.0 broker integration test.
//!
//! Run with a broker available:
//! `cargo test -p hopf-amqp1 --features integration -- --nocapture`
//!
//! Targets a broker with native AMQP 1.0 support — RabbitMQ 4 (default,
//! `/queues/<name>` node addressing) or ActiveMQ Artemis (plain queue-name
//! addressing; set `HOPF_AMQP1_ADDRESS_STYLE=artemis`).
//!
//! Env overrides: `HOPF_AMQP1_HOST`, `HOPF_AMQP1_PORT`, `HOPF_AMQP1_USER`,
//! `HOPF_AMQP1_PASS`, `HOPF_AMQP1_ADDRESS_STYLE` (`rabbitmq` default | `artemis`).

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hopf_core::{Runtime, RuntimeConfig};

use crate::client::{Amqp1Client, Amqp1ClientControl, Amqp1ClientDriver, Amqp1ClientHandlerFactory};
use crate::codec::{DeliveryState, MessageHeader, MessageProperties, Source, Target};

fn broker_creds() -> (String, u16, String, String) {
    let host = std::env::var("HOPF_AMQP1_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("HOPF_AMQP1_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(5672);
    let user = std::env::var("HOPF_AMQP1_USER").unwrap_or_else(|_| "guest".into());
    let pass = std::env::var("HOPF_AMQP1_PASS").unwrap_or_else(|_| "guest".into());
    (host, port, user, pass)
}

/// Node address for `queue`, in whichever style this broker expects — RabbitMQ
/// 4's native AMQP 1.0 support uses `/queues/<name>` (percent-encoding not
/// needed for the plain alphanumeric names this test uses); Artemis and most
/// other AMQP 1.0 brokers just use the plain queue name.
fn node_address(queue: &str) -> String {
    match std::env::var("HOPF_AMQP1_ADDRESS_STYLE").as_deref() {
        Ok("artemis") => queue.to_string(),
        _ => format!("/queues/{queue}"),
    }
}

#[derive(Default, Clone)]
struct State {
    opened: bool,
    sender_attached: bool,
    receiver_attached: bool,
    sent: bool,
    outcome_settled: bool,
    received_body: Vec<u8>,
    received_content_type: Option<String>,
    delivered: bool,
    error: Option<String>,
}

struct RoundTripDriver {
    queue: String,
    state: Arc<Mutex<State>>,
    sender_handle: Option<u32>,
    receiver_handle: Option<u32>,
}

impl Amqp1ClientDriver for RoundTripDriver {
    fn on_connection_open(&mut self, control: &mut dyn Amqp1ClientControl) {
        self.state.lock().unwrap().opened = true;
        control.begin_session();
    }

    fn on_session_begin(&mut self, control: &mut dyn Amqp1ClientControl, channel: u16) {
        let address = node_address(&self.queue);
        self.sender_handle = Some(control.attach_sender(channel, "hopf-amqp1-integ-sender", Target::with_address(&address)));
        self.receiver_handle =
            Some(control.attach_receiver(channel, "hopf-amqp1-integ-receiver", Source::with_address(&address)));
    }

    fn on_link_attached(&mut self, control: &mut dyn Amqp1ClientControl, handle: u32, is_receiver: bool) {
        if is_receiver {
            self.state.lock().unwrap().receiver_attached = true;
            control.add_credit(handle, 10);
        } else {
            self.state.lock().unwrap().sender_attached = true;
        }
    }

    fn on_credit(&mut self, control: &mut dyn Amqp1ClientControl, handle: u32) {
        if Some(handle) != self.sender_handle {
            return;
        }
        let mut s = self.state.lock().unwrap();
        if s.sent {
            return;
        }
        let header = MessageHeader { durable: false, ..Default::default() };
        let properties = MessageProperties { content_type: Some("text/plain".into()), ..Default::default() };
        let result = control.send(
            handle,
            b"hopf-amqp1-integ-tag",
            Some(&header),
            Some(&properties),
            &[],
            b"hopf-amqp1 integration round trip",
            false,
        );
        s.sent = result.is_ok();
        if let Err(e) = result {
            s.error = Some(e.to_string());
        }
    }

    fn on_message_properties(&mut self, _handle: u32, properties: &MessageProperties) {
        self.state.lock().unwrap().received_content_type = properties.content_type.clone();
    }

    fn on_message_data(&mut self, _handle: u32, data: &[u8]) {
        self.state.lock().unwrap().received_body.extend_from_slice(data);
    }

    fn on_delivery_complete(&mut self, control: &mut dyn Amqp1ClientControl, handle: u32, delivery_id: u32) {
        control.accept(handle, delivery_id);
        self.state.lock().unwrap().delivered = true;
    }

    fn on_delivery_outcome(&mut self, _handle: u32, _delivery_tag: &[u8], state: &DeliveryState, settled: bool) {
        if matches!(state, DeliveryState::Accepted) && settled {
            self.state.lock().unwrap().outcome_settled = true;
        }
    }

    fn on_error(&mut self, err: &std::io::Error) {
        self.state.lock().unwrap().error = Some(err.to_string());
    }

    fn on_disconnected(&mut self) {}
}

struct RoundTripFactory {
    queue: String,
    state: Arc<Mutex<State>>,
}

impl Amqp1ClientHandlerFactory for RoundTripFactory {
    fn create(&self) -> Box<dyn Amqp1ClientDriver> {
        Box::new(RoundTripDriver {
            queue: self.queue.clone(),
            state: Arc::clone(&self.state),
            sender_handle: None,
            receiver_handle: None,
        })
    }
}

fn wait_for(
    state: &Arc<Mutex<State>>,
    deadline_secs: u64,
    done: impl Fn(&State) -> bool,
    label: &str,
) -> State {
    let deadline = Instant::now() + Duration::from_secs(deadline_secs);
    loop {
        {
            let s = state.lock().unwrap();
            if let Some(e) = &s.error {
                panic!("amqp1 error: {e}");
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

/// Attaches a sender and a receiver to the same queue's node address (a
/// broker-side queue routes a message a client sends to itself back to that
/// same client), sends one message, and confirms it round-trips with its
/// properties and body intact, and that the broker settles the send as
/// accepted.
#[test]
fn publish_consume_roundtrip() {
    let (host, port, user, pass) = broker_creds();
    let queue = format!("hopf.amqp1.integ.{}", std::process::id());

    let state = Arc::new(Mutex::new(State::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    Amqp1Client::new(host, port)
        .credentials(user, pass)
        .connect(&rt, Arc::new(RoundTripFactory { queue, state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(&state, 15, |s| s.delivered && s.outcome_settled, "publish/consume round-trip");

    assert!(s.opened);
    assert!(s.sender_attached && s.receiver_attached);
    assert!(s.sent);
    assert_eq!(s.received_content_type.as_deref(), Some("text/plain"));
    assert_eq!(s.received_body, b"hopf-amqp1 integration round trip");
}

/// Same round-trip, but over implicit TLS (`amqps://`, typically port 5671)
/// against the broker's leaf certificate, trusting a throwaway local CA the
/// same way `hopf-amqp`'s own TLS integration test does — not a bypass of
/// certificate verification. Skipped if that CA file isn't present, since
/// amqps isn't part of every dev environment's broker setup.
#[test]
fn amqps_publish_consume_roundtrip_over_implicit_tls() {
    let (host, _plain_port, user, pass) = broker_creds();
    let tls_port: u16 = std::env::var("HOPF_AMQP1_TLS_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(5671);
    let ca_path = std::env::var("HOPF_AMQP1_TLS_CA").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        let home = std::env::var("HOME").expect("HOME not set");
        std::path::PathBuf::from(home).join(".hopf-rabbitmq-tls/ca-cert.pem")
    });
    if !ca_path.exists() {
        eprintln!("skipping amqps_publish_consume_roundtrip_over_implicit_tls: no CA cert at {}", ca_path.display());
        return;
    }
    let connector = hopf_core::connector_from_pem(&ca_path, &[]).expect("tls connector");

    let queue = format!("hopf.amqp1.integ.tls.{}", std::process::id());
    let state = Arc::new(Mutex::new(State::default()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).expect("runtime"));
    Amqp1Client::new(host, tls_port)
        .credentials(user, pass)
        .implicit_tls(connector, "localhost")
        .connect(&rt, Arc::new(RoundTripFactory { queue, state: Arc::clone(&state) }))
        .expect("connect");

    let s = wait_for(&state, 15, |s| s.delivered && s.outcome_settled, "amqps publish/consume round-trip");
    assert!(s.opened);
    assert_eq!(s.received_body, b"hopf-amqp1 integration round trip");
}
