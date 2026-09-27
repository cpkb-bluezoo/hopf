// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async AMQP 1.0 client — `hopf-core` `Runtime` / `ProtocolHandler` based.
//!
//! The primary entry points are:
//! - [`Amqp1Client`] — high-level facade (DNS + `Runtime::connect`)
//! - [`Amqp1ClientDriver`] — consolidated callback trait for the connection lifecycle
//! - [`Amqp1ClientControl`] — session/link/message operations, passed to the driver
//!
//! # Quick start
//!
//! ```no_run
//! use std::sync::Arc;
//! use hopf_core::{Runtime, RuntimeConfig};
//! use hopf_amqp1::client::{Amqp1Client, Amqp1ClientControl, Amqp1ClientDriver, Amqp1ClientHandlerFactory};
//! use hopf_amqp1::codec::{MessageProperties, Source, Target};
//!
//! struct Driver { channel: u16, sender: u32 }
//! impl Amqp1ClientDriver for Driver {
//!     fn on_connection_open(&mut self, control: &mut dyn Amqp1ClientControl) {
//!         self.channel = control.begin_session();
//!     }
//!     fn on_session_begin(&mut self, control: &mut dyn Amqp1ClientControl, channel: u16) {
//!         self.sender = control.attach_sender(channel, "my-link", Target::with_address("orders"));
//!     }
//!     fn on_credit(&mut self, control: &mut dyn Amqp1ClientControl, handle: u32) {
//!         let mut props = MessageProperties::default();
//!         props.content_type = Some("text/plain".into());
//!         let _ = control.send(handle, b"tag-1", None, Some(&props), &[], b"hello amqp 1.0", true);
//!     }
//!     fn on_error(&mut self, err: &std::io::Error) { eprintln!("amqp1 error: {err}"); }
//!     fn on_disconnected(&mut self) {}
//! }
//! struct Factory;
//! impl Amqp1ClientHandlerFactory for Factory {
//!     fn create(&self) -> Box<dyn Amqp1ClientDriver> { Box::new(Driver { channel: 0, sender: 0 }) }
//! }
//!
//! let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
//! Amqp1Client::new("broker.example.com", 5672)
//!     .connect(&rt, Arc::new(Factory))
//!     .unwrap();
//! ```

mod endpoint;
mod error;
mod facade;
mod handlers;
mod session;
#[cfg(test)]
mod tests;
mod timeout;

pub use endpoint::{Amqp1ClientEndpoint, Amqp1ClientParams};
pub use error::{Amqp1ClientError, Amqp1ClientResult};
pub use facade::Amqp1Client;
pub use handlers::{Amqp1ClientControl, Amqp1ClientDriver, Amqp1ClientHandlerFactory};
pub use timeout::Amqp1ClientTimeouts;
