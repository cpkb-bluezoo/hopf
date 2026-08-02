// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async AMQP 0-9-1 client — `hopf-core` `Runtime` / `ProtocolHandler` based.
//!
//! The primary entry points are:
//! - [`AmqpClient`] — high-level facade (DNS + `Runtime::connect`)
//! - [`AmqpClientDriver`] — callback trait for the connection lifecycle
//! - [`AmqpClientControl`] — channel / topology / publish / consume actions
//!
//! # Quick start
//!
//! ```no_run
//! use std::sync::Arc;
//! use hopf_core::{Runtime, RuntimeConfig};
//! use hopf_amqp::client::{AmqpClient, AmqpClientControl, AmqpClientDriver, AmqpClientHandlerFactory};
//! use hopf_amqp::codec::{BasicProperties, FieldTable};
//!
//! struct Driver;
//! impl AmqpClientDriver for Driver {
//!     fn on_connection_open(&mut self, client: &mut dyn AmqpClientControl) {
//!         client.channel_open(1);
//!     }
//!     fn on_channel_open(&mut self, client: &mut dyn AmqpClientControl, channel: u16) {
//!         client.queue_declare(channel, "demo", false, false, true, true, &FieldTable::new());
//!     }
//!     fn on_channel_close(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: u16, _: &str) {}
//!     fn on_exchange_declare_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}
//!     fn on_queue_declare_ok(&mut self, client: &mut dyn AmqpClientControl, channel: u16, queue: &str, _: u32, _: u32) {
//!         client.basic_publish(channel, "", queue, false, false, &BasicProperties::new(), b"hi");
//!     }
//!     fn on_consume_ok(&mut self, _: &mut dyn AmqpClientControl, _: u16, _: &str) {}
//!     fn on_delivery_start(&mut self, _: u16, _: &str, _: u64, _: bool, _: &str, _: &str, _: &BasicProperties, _: u64) {}
//!     fn on_delivery_data(&mut self, _: &[u8]) {}
//!     fn on_delivery_complete(&mut self, _: &mut dyn AmqpClientControl, _: u16) {}
//!     fn on_error(&mut self, err: &std::io::Error) { eprintln!("{err}"); }
//!     fn on_disconnected(&mut self) {}
//! }
//! struct Factory;
//! impl AmqpClientHandlerFactory for Factory {
//!     fn create(&self) -> Box<dyn AmqpClientDriver> { Box::new(Driver) }
//! }
//!
//! let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
//! AmqpClient::new("127.0.0.1", 5672).connect(&rt, Arc::new(Factory)).unwrap();
//! ```

mod endpoint;
mod error;
mod facade;
mod handlers;
mod timeout;

pub use endpoint::{AmqpClientEndpoint, AmqpClientParams};
pub use error::{AmqpClientError, AmqpClientResult};
pub use facade::AmqpClient;
pub use handlers::{AmqpClientControl, AmqpClientDriver, AmqpClientHandlerFactory};
pub use timeout::AmqpClientTimeouts;
