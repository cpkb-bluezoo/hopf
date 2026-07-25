// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT client demo: subscribe to a topic, publish once, print anything
//! received (including its own echo, since No Local isn't requested).
//!
//! ```text
//! # Against a local broker (e.g. the mqtt example):
//! cargo run -p mqtt-pub -- 127.0.0.1 1883 demo/topic "hello from hopf"
//! ```

use std::env;
use std::io;
use std::sync::Arc;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_mqtt::client::{MqttClient, MqttClientControl, MqttClientDriver, MqttClientHandlerFactory};
use hopf_mqtt::codec::{Properties, QoS, SubscribeFilter};

struct PubSubDriver {
    topic: String,
    payload: Vec<u8>,
}

impl MqttClientDriver for PubSubDriver {
    fn on_connack(&mut self, client: &mut dyn MqttClientControl, session_present: bool, reason_code: u8, _properties: &Properties) {
        if reason_code != 0 {
            eprintln!("CONNECT refused, reason code {reason_code}");
            return;
        }
        eprintln!("connected (session_present={session_present}); subscribing to {}", self.topic);
        client.subscribe(&[SubscribeFilter {
            topic_filter: self.topic.clone(),
            max_qos: QoS::AtLeastOnce,
            no_local: false,
            retain_as_published: false,
            retain_handling: 0,
        }]);
    }

    fn on_suback(&mut self, client: &mut dyn MqttClientControl, _packet_id: u16, reason_codes: &[u8]) {
        eprintln!("subscribed (reason codes {reason_codes:?}); publishing to {}", self.topic);
        client.publish(&self.topic, &self.payload, QoS::AtLeastOnce, false, &Properties::new());
    }

    fn on_message_start(&mut self, topic: &str, qos: QoS, retain: bool, _packet_id: u16, _properties: &Properties, payload_len: u32) {
        print!("── PUBLISH {topic} (qos={}, retain={retain}, {payload_len} bytes): ", qos.value());
    }

    fn on_message_data(&mut self, data: &[u8]) {
        print!("{}", String::from_utf8_lossy(data));
    }

    fn on_message_complete(&mut self, _client: &mut dyn MqttClientControl) {
        println!();
    }

    fn on_unsuback(&mut self, _client: &mut dyn MqttClientControl, _packet_id: u16, _reason_codes: &[u8]) {}

    fn on_publish_acked(&mut self, _client: &mut dyn MqttClientControl, packet_id: u16) {
        eprintln!("publish {packet_id} acked");
    }

    fn on_ping_resp(&mut self, _client: &mut dyn MqttClientControl) {}

    fn on_server_disconnect(&mut self, reason_code: u8, _properties: &Properties) {
        eprintln!("server disconnected us, reason code {reason_code}");
    }

    fn on_error(&mut self, err: &io::Error) {
        eprintln!("client error: {err}");
    }

    fn on_disconnected(&mut self) {
        eprintln!("disconnected");
    }
}

struct PubSubFactory {
    topic: String,
    payload: Vec<u8>,
}

impl MqttClientHandlerFactory for PubSubFactory {
    fn create(&self) -> Box<dyn MqttClientDriver> {
        Box::new(PubSubDriver {
            topic: self.topic.clone(),
            payload: self.payload.clone(),
        })
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: mqtt-pub <host> <port> <topic> <payload>");
        return Ok(());
    }
    let host = args[1].clone();
    let port: u16 = args[2]
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let topic = args[3].clone();
    let payload = args[4].clone().into_bytes();

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    let client_id = format!("hopf-mqtt-pub-{}", std::process::id());

    MqttClient::new(host, port, client_id).connect(
        &rt,
        Arc::new(PubSubFactory { topic, payload }),
    )?;

    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    drop(rt);
    Ok(())
}
