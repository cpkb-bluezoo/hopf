// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP publish demo: declare a queue, enable confirms, publish one message.
//!
//! ```text
//! cargo run -p amqp-pub -- 127.0.0.1 5672 demo.queue "hello from hopf"
//! ```

use std::env;
use std::io;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hopf_amqp::client::{
    AmqpClient, AmqpClientControl, AmqpClientDriver, AmqpClientHandlerFactory,
};
use hopf_amqp::codec::{BasicProperties, FieldTable};
use hopf_core::{Runtime, RuntimeConfig};

struct PubDriver {
    queue: String,
    payload: Vec<u8>,
    done: bool,
}

impl AmqpClientDriver for PubDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.confirm_select(channel);
        client.queue_declare(
            channel,
            &self.queue,
            false,
            false,
            false,
            false,
            &FieldTable::new(),
        );
    }

    fn on_channel_close(
        &mut self,
        _client: &mut dyn AmqpClientControl,
        channel: u16,
        reply_code: u16,
        reply_text: &str,
    ) {
        eprintln!("channel {channel} closed: {reply_code} {reply_text}");
    }

    fn on_exchange_declare_ok(&mut self, _client: &mut dyn AmqpClientControl, _channel: u16) {}

    fn on_confirm_select_ok(&mut self, _client: &mut dyn AmqpClientControl, channel: u16) {
        eprintln!("confirms enabled on channel {channel}");
    }

    fn on_queue_declare_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        queue: &str,
        _message_count: u32,
        _consumer_count: u32,
    ) {
        eprintln!("queue declared: {queue}; publishing");
        let mut props = BasicProperties::new();
        props.content_type = Some("text/plain".into());
        client.basic_publish(
            channel,
            "",
            queue,
            false,
            false,
            &props,
            &self.payload,
        );
    }

    fn on_ack(
        &mut self,
        client: &mut dyn AmqpClientControl,
        _channel: u16,
        delivery_tag: u64,
        _multiple: bool,
    ) {
        eprintln!("publish acked (delivery_tag={delivery_tag})");
        self.done = true;
        client.connection_close(200, "bye");
    }

    fn on_consume_ok(&mut self, _client: &mut dyn AmqpClientControl, _channel: u16, _tag: &str) {}

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

    fn on_error(&mut self, err: &io::Error) {
        eprintln!("amqp error: {err}");
    }

    fn on_disconnected(&mut self) {
        eprintln!("disconnected");
    }
}

struct PubFactory {
    queue: String,
    payload: Vec<u8>,
}

impl AmqpClientHandlerFactory for PubFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(PubDriver {
            queue: self.queue.clone(),
            payload: self.payload.clone(),
            done: false,
        })
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: amqp-pub <host> <port> <queue> <payload>");
        return Ok(());
    }
    let host = args[1].clone();
    let port: u16 = args[2]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?;
    let queue = args[3].clone();
    let payload = args[4].clone().into_bytes();

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    AmqpClient::new(host, port)
        .connect(
            &rt,
            Arc::new(PubFactory {
                queue,
                payload,
            }),
        )?;

    // Keep process alive briefly for the async handshake / publish.
    thread::sleep(Duration::from_secs(5));
    Ok(())
}
