// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP consume demo: declare a queue and print deliveries until interrupted.
//!
//! ```text
//! cargo run -p amqp-consume -- 127.0.0.1 5672 demo.queue
//! ```

use std::env;
use std::io;
use std::io::Write;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hopf_amqp::client::{
    AmqpClient, AmqpClientControl, AmqpClientDriver, AmqpClientHandlerFactory,
};
use hopf_amqp::codec::{BasicProperties, FieldTable};
use hopf_core::{Runtime, RuntimeConfig};

struct ConsumeDriver {
    queue: String,
    pending_tag: Option<(u16, u64)>,
}

impl AmqpClientDriver for ConsumeDriver {
    fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
        client.channel_open(1);
    }

    fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        client.basic_qos(channel, 0, 10, false);
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

    fn on_queue_declare_ok(
        &mut self,
        client: &mut dyn AmqpClientControl,
        channel: u16,
        queue: &str,
        _message_count: u32,
        _consumer_count: u32,
    ) {
        eprintln!("consuming from {queue}");
        client.basic_consume(
            channel,
            queue,
            "",
            false,
            false,
            false,
            &FieldTable::new(),
        );
    }

    fn on_consume_ok(&mut self, _client: &mut dyn AmqpClientControl, channel: u16, tag: &str) {
        eprintln!("consume-ok channel={channel} tag={tag}");
    }

    fn on_delivery_start(
        &mut self,
        channel: u16,
        consumer_tag: &str,
        delivery_tag: u64,
        redelivered: bool,
        exchange: &str,
        routing_key: &str,
        properties: &BasicProperties,
        body_len: u64,
    ) {
        let ctype = properties
            .content_type
            .as_deref()
            .unwrap_or("-");
        print!(
            "── deliver ch={channel} tag={delivery_tag} consumer={consumer_tag} \
             redelivered={redelivered} exchange={exchange} rk={routing_key} \
             content-type={ctype} ({body_len} bytes): "
        );
        let _ = io::stdout().flush();
        self.pending_tag = Some((channel, delivery_tag));
    }

    fn on_delivery_data(&mut self, _channel: u16, data: &[u8]) {
        print!("{}", String::from_utf8_lossy(data));
        let _ = io::stdout().flush();
    }

    fn on_delivery_complete(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
        println!();
        if let Some((ch, tag)) = self.pending_tag.take() {
            if ch == channel {
                client.basic_ack(channel, tag, false);
            }
        }
    }

    fn on_error(&mut self, err: &io::Error) {
        eprintln!("amqp error: {err}");
    }

    fn on_disconnected(&mut self) {
        eprintln!("disconnected");
    }
}

struct ConsumeFactory {
    queue: String,
}

impl AmqpClientHandlerFactory for ConsumeFactory {
    fn create(&self) -> Box<dyn AmqpClientDriver> {
        Box::new(ConsumeDriver {
            queue: self.queue.clone(),
            pending_tag: None,
        })
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: amqp-consume <host> <port> <queue>");
        return Ok(());
    }
    let host = args[1].clone();
    let port: u16 = args[2]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?;
    let queue = args[3].clone();

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    AmqpClient::new(host, port).connect(&rt, Arc::new(ConsumeFactory { queue }))?;

    // Block the main thread; deliveries arrive on reactor threads.
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
