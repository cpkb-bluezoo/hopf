// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT broker demo (3.1.1 + v5 core), plain TCP.
//!
//! ```text
//! cargo run -p mqtt -- 127.0.0.1:1883
//! ```
//!
//! No CONNECT authorization by default — pass `MqttConfig::with_credentials`
//! (see `hopf-pop3`'s example for the `PasswordStore` pattern) or a custom
//! `MqttHandlerFactory` to require auth.

use std::env;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_mqtt::server::broker::BrokerState;
use hopf_mqtt::server::{MqttConfig, MqttService};

fn main() -> io::Result<()> {
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:1883".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    let broker = Arc::new(BrokerState::new());
    let config = MqttConfig::new(addr, broker);
    let svc = MqttService::new(config);
    let bound = svc.start(&rt)?;

    eprintln!("mqtt broker on mqtt://{bound}/  (no auth — CONNECT accepted from anyone)");
    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    drop(rt);
    Ok(())
}
