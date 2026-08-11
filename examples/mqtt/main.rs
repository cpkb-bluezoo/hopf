// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT broker demo (3.1.1 + v5 core), plain TCP.
//!
//! ```text
//! cargo run -p mqtt -- 127.0.0.1:1883
//! ```
//!
//! This demo calls [`MqttConfig::allow_anonymous`] so CONNECT works without
//! a credential store. Production brokers should use
//! [`MqttConfig::with_credentials`] instead (and omit `allow_anonymous`).

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
    let config = MqttConfig::new(addr, broker).allow_anonymous();
    let svc = MqttService::new(config);
    let bound = svc.start(Arc::clone(&rt))?;

    eprintln!("mqtt broker on mqtt://{bound}/  (anonymous CONNECT — demo only)");
    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    drop(rt);
    Ok(())
}
